package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// FlowCache manages flow data storage in Redis
type FlowCache struct {
	client     *redis.Client
	logger     *logrus.Logger
	mu         sync.RWMutex
	flowBuffer chan *Flow
	ctx        context.Context
	cancel     context.CancelFunc
}

// FlowWindow represents a time window of flows for a specific key
type FlowWindow struct {
	Key       string    `json:"key"`
	Flows     []Flow    `json:"flows"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Count     int       `json:"count"`
}

// FlowMetrics represents aggregated metrics for anomaly detection
type FlowMetrics struct {
	Key             string    `json:"key"`
	TotalFlows      int64     `json:"total_flows"`
	TotalBytes      int64     `json:"total_bytes"`
	ErrorCount      int64     `json:"error_count"`
	ConnectionCount int64     `json:"connection_count"`
	AverageLatency  float64   `json:"average_latency"`
	ErrorRate       float64   `json:"error_rate"`
	ByteRate        float64   `json:"byte_rate"`
	FlowRate        float64   `json:"flow_rate"`
	LastUpdated     time.Time `json:"last_updated"`
	WindowDuration  int64     `json:"window_duration_seconds"`
}

// Redis configuration
const (
	RedisAddr     = "127.0.0.1:6379"
	RedisPassword = "hoangcn8uetvnu"
	RedisDB       = 0

	// Redis key patterns
	FlowKeyPrefix    = "hubble:flow:"
	MetricsKeyPrefix = "hubble:metrics:"
	WindowKeyPrefix  = "hubble:window:"

	// Time windows
	DefaultWindowDuration = 60  // seconds
	MaxWindowDuration     = 300 // 5 minutes
	BufferSize            = 1000
)

// NewFlowCache creates a new FlowCache with Redis connection
func NewFlowCache(logger *logrus.Logger) (*FlowCache, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:     RedisAddr,
		Password: RedisPassword,
		DB:       RedisDB,
	})

	// Test connection
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	fc := &FlowCache{
		client:     rdb,
		logger:     logger,
		flowBuffer: make(chan *Flow, BufferSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start background workers
	go fc.flowProcessor()
	go fc.cleanupWorker()

	logger.Info("FlowCache initialized with Redis connection")
	return fc, nil
}

// AddFlow adds a flow to the cache buffer
func (fc *FlowCache) AddFlow(flow *Flow) {
	select {
	case fc.flowBuffer <- flow:
		// Flow added to buffer successfully
	default:
		fc.logger.Warn("Flow buffer is full, dropping flow")
	}
}

// flowProcessor processes flows from the buffer and stores them in Redis
func (fc *FlowCache) flowProcessor() {
	for {
		select {
		case flow := <-fc.flowBuffer:
			fc.storeFlow(flow)
		case <-fc.ctx.Done():
			fc.logger.Info("Flow processor stopped")
			return
		}
	}
}

// storeFlow stores a single flow in Redis
func (fc *FlowCache) storeFlow(flow *Flow) {
	if flow == nil {
		return
	}

	// Create flow key based on source-destination
	key := fc.generateFlowKey(flow)

	// Serialize flow to JSON
	flowJSON, err := json.Marshal(flow)
	if err != nil {
		fc.logger.Errorf("Failed to marshal flow: %v", err)
		return
	}

	// Store flow with TTL (expire after 5 minutes)
	ttl := time.Duration(MaxWindowDuration) * time.Second
	err = fc.client.Set(fc.ctx, key, flowJSON, ttl).Err()
	if err != nil {
		fc.logger.Errorf("Failed to store flow in Redis: %v", err)
		return
	}

	// Add to time-based window
	fc.addToWindow(key, flow)
}

// generateFlowKey creates a unique key for a flow
func (fc *FlowCache) generateFlowKey(flow *Flow) string {
	if flow.IP != nil {
		// Use IP-based key for network flows
		return fmt.Sprintf("%s%s:%s", FlowKeyPrefix, flow.IP.Source, flow.IP.Destination)
	} else if flow.Source != nil && flow.Destination != nil {
		// Use pod-based key for service flows
		return fmt.Sprintf("%s%s:%s", FlowKeyPrefix, flow.Source.PodName, flow.Destination.PodName)
	}

	// Fallback to timestamp-based key
	return fmt.Sprintf("%s%d", FlowKeyPrefix, time.Now().UnixNano())
}

// addToWindow adds flow to a time window for aggregation
func (fc *FlowCache) addToWindow(key string, flow *Flow) {
	windowKey := fmt.Sprintf("%s%s", WindowKeyPrefix, key)

	// Add flow to sorted set with timestamp as score
	score := float64(time.Now().Unix())
	flowJSON, _ := json.Marshal(flow)

	err := fc.client.ZAdd(fc.ctx, windowKey, &redis.Z{
		Score:  score,
		Member: flowJSON,
	}).Err()

	if err != nil {
		fc.logger.Errorf("Failed to add flow to window: %v", err)
		return
	}

	// Set TTL for window
	ttl := time.Duration(MaxWindowDuration) * time.Second
	fc.client.Expire(fc.ctx, windowKey, ttl)
}

// GetFlowMetrics retrieves aggregated metrics for a specific key
func (fc *FlowCache) GetFlowMetrics(key string, windowDuration int64) (*FlowMetrics, error) {
	if windowDuration <= 0 {
		windowDuration = DefaultWindowDuration
	}
	if windowDuration > MaxWindowDuration {
		windowDuration = MaxWindowDuration
	}

	windowKey := fmt.Sprintf("%s%s", WindowKeyPrefix, key)

	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get flows in time window
	flows, err := fc.client.ZRangeByScore(fc.ctx, windowKey, &redis.ZRangeBy{
		Min: fmt.Sprintf("%.0f", cutoffScore),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Calculate metrics
	metrics := &FlowMetrics{
		Key:            key,
		WindowDuration: windowDuration,
		LastUpdated:    time.Now(),
	}

	for _, flowJSON := range flows {
		var flow Flow
		if err := json.Unmarshal([]byte(flowJSON), &flow); err != nil {
			fc.logger.Warnf("Failed to unmarshal flow: %v", err)
			continue
		}

		metrics.TotalFlows++
		metrics.TotalBytes += fc.calculateBytes(&flow)

		// Count errors
		if flow.Verdict == Verdict_DROPPED || flow.Verdict == Verdict_ERROR {
			metrics.ErrorCount++
		}

		// Count connections
		if flow.Type == FlowType_L3_L4 || flow.Type == FlowType_L7 {
			metrics.ConnectionCount++
		}
	}

	// Calculate rates
	if windowDuration > 0 {
		metrics.FlowRate = float64(metrics.TotalFlows) / float64(windowDuration)
		metrics.ByteRate = float64(metrics.TotalBytes) / float64(windowDuration)
	}

	if metrics.TotalFlows > 0 {
		metrics.ErrorRate = float64(metrics.ErrorCount) / float64(metrics.TotalFlows) * 100
	}

	return metrics, nil
}

// GetFlowWindows retrieves all flow windows for analysis
func (fc *FlowCache) GetFlowWindows(windowDuration int64) ([]*FlowWindow, error) {
	if windowDuration <= 0 {
		windowDuration = DefaultWindowDuration
	}

	// Get all window keys
	pattern := fmt.Sprintf("%s*", WindowKeyPrefix)
	keys, err := fc.client.Keys(fc.ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get window keys: %v", err)
	}

	var windows []*FlowWindow
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	for _, key := range keys {
		// Get flows in time window
		flows, err := fc.client.ZRangeByScore(fc.ctx, key, &redis.ZRangeBy{
			Min: fmt.Sprintf("%.0f", cutoffScore),
			Max: "+inf",
		}).Result()

		if err != nil {
			fc.logger.Warnf("Failed to get flows for key %s: %v", key, err)
			continue
		}

		if len(flows) == 0 {
			continue
		}

		// Parse flows
		var parsedFlows []Flow
		for _, flowJSON := range flows {
			var flow Flow
			if err := json.Unmarshal([]byte(flowJSON), &flow); err != nil {
				continue
			}
			parsedFlows = append(parsedFlows, flow)
		}

		// Create window
		window := &FlowWindow{
			Key:       key[len(WindowKeyPrefix):], // Remove prefix
			Flows:     parsedFlows,
			StartTime: cutoffTime,
			EndTime:   time.Now(),
			Count:     len(parsedFlows),
		}

		windows = append(windows, window)
	}

	return windows, nil
}

// calculateBytes estimates bytes from flow data
func (fc *FlowCache) calculateBytes(flow *Flow) int64 {
	if flow.L4 != nil {
		if flow.L4.TCP != nil {
			return int64(flow.L4.TCP.Bytes)
		}
		if flow.L4.UDP != nil {
			return int64(flow.L4.UDP.Bytes)
		}
	}
	return 0
}

// cleanupWorker periodically cleans up expired data
func (fc *FlowCache) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fc.cleanupExpiredData()
		case <-fc.ctx.Done():
			return
		}
	}
}

// cleanupExpiredData removes expired flow data
func (fc *FlowCache) cleanupExpiredData() {
	// Redis TTL handles most cleanup, but we can do additional cleanup here
	// For example, remove empty windows
	pattern := fmt.Sprintf("%s*", WindowKeyPrefix)
	keys, err := fc.client.Keys(fc.ctx, pattern).Result()
	if err != nil {
		fc.logger.Errorf("Failed to get keys for cleanup: %v", err)
		return
	}

	for _, key := range keys {
		count, err := fc.client.ZCard(fc.ctx, key).Result()
		if err != nil {
			continue
		}

		if count == 0 {
			fc.client.Del(fc.ctx, key)
		}
	}
}

// Close closes the FlowCache and cleans up resources
func (fc *FlowCache) Close() error {
	fc.cancel()
	close(fc.flowBuffer)
	return fc.client.Close()
}

// GetStats returns cache statistics
func (fc *FlowCache) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get Redis info
	info, err := fc.client.Info(fc.ctx).Result()
	if err != nil {
		return nil, err
	}

	stats["redis_info"] = info
	stats["buffer_size"] = len(fc.flowBuffer)
	stats["buffer_capacity"] = cap(fc.flowBuffer)

	// Count keys
	flowKeys, _ := fc.client.Keys(fc.ctx, fmt.Sprintf("%s*", FlowKeyPrefix)).Result()
	windowKeys, _ := fc.client.Keys(fc.ctx, fmt.Sprintf("%s*", WindowKeyPrefix)).Result()

	stats["flow_keys_count"] = len(flowKeys)
	stats["window_keys_count"] = len(windowKeys)

	return stats, nil
}
