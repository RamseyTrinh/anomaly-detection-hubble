package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// FlowCache manages flow data storage in Redis
type FlowCache struct {
	client     *redis.Client
	logger     *logrus.Logger
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
	FlowKeyPrefix    = "flow:"
	MetricsKeyPrefix = "hubble:metrics:"
	WindowKeyPrefix  = "hubble:window:"
	VerdictKeyPrefix = "flow:"
	FlagsKeyPrefix   = "flow:"

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

	return fc, nil
}

func (fc *FlowCache) AddFlow(flow *Flow) {
	select {
	case fc.flowBuffer <- flow:

	default:
		fc.logger.Warn("Flow buffer is full, dropping flow")
	}
}

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

// storeFlow stores a single flow in Redis using Sorted Set
func (fc *FlowCache) storeFlow(flow *Flow) {
	if flow == nil {
		return
	}

	// Create flow key based on source-destination pods
	key := fc.generateFlowKey(flow)

	// Get timestamp for sorting
	timestamp := time.Now().Unix()
	if flow.Time != nil {
		timestamp = flow.Time.Unix()
	}

	// Create value with port|flags|verdict encoding
	value := fc.encodeFlowValue(flow)

	// Store in Sorted Set with timestamp as score
	err := fc.client.ZAdd(fc.ctx, key, &redis.Z{
		Score:  float64(timestamp),
		Member: value,
	}).Err()
	if err != nil {
		fc.logger.Errorf("Failed to store flow in Redis: %v", err)
		return
	}

	// Set TTL for the key (expire after 10 minutes)
	ttl := time.Duration(10) * time.Minute
	fc.client.Expire(fc.ctx, key, ttl)

	// Add to verdict and flags indexes
	fc.addToIndexes(key, flow, timestamp)

	// No bucket counting needed for new rules
}

// generateFlowKey creates a unique key for a flow using pod names
func (fc *FlowCache) generateFlowKey(flow *Flow) string {
	var srcPod, dstPod string

	// Extract source pod name
	if flow.Source != nil && flow.Source.PodName != "" {
		srcPod = flow.Source.PodName
	} else if flow.IP != nil {
		srcPod = flow.IP.Source
	} else {
		srcPod = "unknown"
	}

	// Extract destination pod name
	if flow.Destination != nil && flow.Destination.PodName != "" {
		dstPod = flow.Destination.PodName
	} else if flow.IP != nil {
		dstPod = flow.IP.Destination
	} else {
		dstPod = "unknown"
	}

	// Return key in format: flow:{srcPod}:{dstPod}
	return fmt.Sprintf("%s%s:%s", FlowKeyPrefix, srcPod, dstPod)
}

// encodeFlowValue encodes flow data into a compact string format
func (fc *FlowCache) encodeFlowValue(flow *Flow) string {
	var port, flags, verdict string

	// Extract port information
	if flow.L4 != nil {
		if flow.L4.TCP != nil {
			port = fmt.Sprintf("%d|%d", flow.L4.TCP.SourcePort, flow.L4.TCP.DestinationPort)
			// Extract TCP flags
			if flow.L4.TCP.Flags != nil {
				var flagList []string
				if flow.L4.TCP.Flags.SYN {
					flagList = append(flagList, "SYN")
				}
				if flow.L4.TCP.Flags.ACK {
					flagList = append(flagList, "ACK")
				}
				if flow.L4.TCP.Flags.FIN {
					flagList = append(flagList, "FIN")
				}
				if flow.L4.TCP.Flags.RST {
					flagList = append(flagList, "RST")
				}
				if flow.L4.TCP.Flags.PSH {
					flagList = append(flagList, "PSH")
				}
				if flow.L4.TCP.Flags.URG {
					flagList = append(flagList, "URG")
				}
				if len(flagList) > 0 {
					flags = strings.Join(flagList, ",")
				}
			}
		} else if flow.L4.UDP != nil {
			port = fmt.Sprintf("%d|%d", flow.L4.UDP.SourcePort, flow.L4.UDP.DestinationPort)
		}
	}

	// Extract verdict
	verdict = flow.Verdict.String()

	// Return encoded value: port|flags|verdict
	return fmt.Sprintf("%s|%s|%s", port, flags, verdict)
}

// addToIndexes adds flow to verdict and flags indexes
func (fc *FlowCache) addToIndexes(key string, flow *Flow, timestamp int64) {
	// Add to verdict index
	verdictKey := fmt.Sprintf("%s%s", VerdictKeyPrefix, flow.Verdict.String())
	fc.client.ZAdd(fc.ctx, verdictKey, &redis.Z{
		Score:  float64(timestamp),
		Member: key,
	})
	fc.client.Expire(fc.ctx, verdictKey, 10*time.Minute)

	// Add to TCP flags indexes if available
	if flow.L4 != nil && flow.L4.TCP != nil && flow.L4.TCP.Flags != nil {
		flags := flow.L4.TCP.Flags
		if flags.SYN {
			fc.addToFlagsIndex("syn", key, timestamp)
		}
		if flags.ACK {
			fc.addToFlagsIndex("ack", key, timestamp)
		}
		if flags.FIN {
			fc.addToFlagsIndex("fin", key, timestamp)
		}
		if flags.RST {
			fc.addToFlagsIndex("rst", key, timestamp)
		}
		if flags.PSH {
			fc.addToFlagsIndex("psh", key, timestamp)
		}
		if flags.URG {
			fc.addToFlagsIndex("urg", key, timestamp)
		}
	}
}

// addToFlagsIndex adds flow to a specific TCP flags index
func (fc *FlowCache) addToFlagsIndex(flag string, key string, timestamp int64) {
	flagsKey := fmt.Sprintf("%s%s", FlagsKeyPrefix, flag)
	fc.client.ZAdd(fc.ctx, flagsKey, &redis.Z{
		Score:  float64(timestamp),
		Member: key,
	})
	fc.client.Expire(fc.ctx, flagsKey, 10*time.Minute)
}

// Connection establishment check removed - not needed for new rules

// GetFlowMetrics retrieves aggregated metrics for a specific key
func (fc *FlowCache) GetFlowMetrics(key string, windowDuration int64) (*FlowMetrics, error) {
	if windowDuration <= 0 {
		windowDuration = DefaultWindowDuration
	}
	if windowDuration > MaxWindowDuration {
		windowDuration = MaxWindowDuration
	}

	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get flows in time window from the main flow key
	flows, err := fc.client.ZRangeByScore(fc.ctx, key, &redis.ZRangeBy{
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

	for _, encodedValue := range flows {
		// Parse encoded value: port|flags|verdict
		parts := strings.Split(encodedValue, "|")
		if len(parts) < 3 {
			continue
		}

		verdictStr := parts[2]
		metrics.TotalFlows++

		// Count errors based on verdict
		if verdictStr == "DROPPED" || verdictStr == "ERROR" {
			metrics.ErrorCount++
		}

		// Count all connections (no unique filtering needed for new rules)
		metrics.ConnectionCount++
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

// GetFlowsByVerdict retrieves flows filtered by verdict
func (fc *FlowCache) GetFlowsByVerdict(verdict string, windowDuration int64) ([]string, error) {
	verdictKey := fmt.Sprintf("%s%s", VerdictKeyPrefix, verdict)

	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get flow keys from verdict index
	flowKeys, err := fc.client.ZRangeByScore(fc.ctx, verdictKey, &redis.ZRangeBy{
		Min: fmt.Sprintf("%.0f", cutoffScore),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get flows by verdict: %v", err)
	}

	return flowKeys, nil
}

// GetFlowsByFlags retrieves flows filtered by TCP flags
func (fc *FlowCache) GetFlowsByFlags(flag string, windowDuration int64) ([]string, error) {
	flagsKey := fmt.Sprintf("%s%s", FlagsKeyPrefix, flag)

	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get flow keys from flags index
	flowKeys, err := fc.client.ZRangeByScore(fc.ctx, flagsKey, &redis.ZRangeBy{
		Min: fmt.Sprintf("%.0f", cutoffScore),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get flows by flags: %v", err)
	}

	return flowKeys, nil
}

// GetFlowData retrieves actual flow data for a specific key
func (fc *FlowCache) GetFlowData(key string, windowDuration int64) ([]string, error) {
	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get encoded flow values
	flows, err := fc.client.ZRangeByScore(fc.ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%.0f", cutoffScore),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get flow data: %v", err)
	}

	return flows, nil
}

// Bucket functions removed - not needed for new rules

// GetUniquePortsForSource gets unique destination ports for a source in time window
func (fc *FlowCache) GetUniquePortsForSource(flowKey string, windowDuration int64) ([]string, error) {
	// Get flows from the last windowDuration seconds
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	// Get flows in time window from the main flow key
	flows, err := fc.client.ZRangeByScore(fc.ctx, flowKey, &redis.ZRangeBy{
		Min: fmt.Sprintf("%.0f", cutoffScore),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Track unique destination ports
	uniquePorts := make(map[string]bool)
	for _, encodedValue := range flows {
		// Parse encoded value: port|flags|verdict
		parts := strings.Split(encodedValue, "|")
		if len(parts) < 3 {
			continue
		}

		portInfo := parts[0] // source_port|dest_port
		portParts := strings.Split(portInfo, "|")
		if len(portParts) >= 2 {
			destPort := portParts[1]
			uniquePorts[destPort] = true
		}
	}

	// Convert map keys to slice
	var ports []string
	for port := range uniquePorts {
		ports = append(ports, port)
	}

	return ports, nil
}

// GetPodNamespaces gets namespace information for source and destination pods
func (fc *FlowCache) GetPodNamespaces(srcPod, dstPod string) (string, string, error) {
	// For now, assume all pods are in "default" namespace
	// In a real implementation, you would query Kubernetes API or cache this information
	return "default", "default", nil
}

// GetFlowWindows retrieves all flow windows for analysis
func (fc *FlowCache) GetFlowWindows(windowDuration int64) ([]*FlowWindow, error) {
	if windowDuration <= 0 {
		windowDuration = DefaultWindowDuration
	}

	// Get all flow keys (not window keys, verdict keys, or flags keys)
	pattern := fmt.Sprintf("%s*", FlowKeyPrefix)
	allKeys, err := fc.client.Keys(fc.ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flow keys: %v", err)
	}

	// Filter out index keys (verdict/flags keys)
	var keys []string
	for _, key := range allKeys {
		// Skip index keys that don't have pod:pod format
		keyWithoutPrefix := key[len(FlowKeyPrefix):]
		if strings.Contains(keyWithoutPrefix, ":") && !strings.Contains(keyWithoutPrefix, "UNKNOWN") &&
			!strings.Contains(keyWithoutPrefix, "FORWARDED") && !strings.Contains(keyWithoutPrefix, "DROPPED") &&
			!strings.Contains(keyWithoutPrefix, "syn") && !strings.Contains(keyWithoutPrefix, "ack") &&
			!strings.Contains(keyWithoutPrefix, "fin") && !strings.Contains(keyWithoutPrefix, "rst") &&
			!strings.Contains(keyWithoutPrefix, "psh") && !strings.Contains(keyWithoutPrefix, "urg") {
			keys = append(keys, key)
		}
	}

	var windows []*FlowWindow
	cutoffTime := time.Now().Add(-time.Duration(windowDuration) * time.Second)
	cutoffScore := float64(cutoffTime.Unix())

	for _, key := range keys {
		// Get flows in time window from flow key
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

		// Parse encoded flows (no unique filtering needed for new rules)
		var parsedFlows []Flow
		flowCount := 0

		for _, encodedValue := range flows {
			// Parse encoded value: port|flags|verdict
			parts := strings.Split(encodedValue, "|")
			if len(parts) < 3 {
				continue
			}

			flowCount++

			// Create a simple flow from encoded value
			flow := Flow{
				Time:    &cutoffTime,
				Verdict: Verdict_FORWARDED, // Default verdict
			}
			parsedFlows = append(parsedFlows, flow)
		}

		// Create window - keep the full key with prefix for consistency
		window := &FlowWindow{
			Key:       key, // Keep full key with prefix
			Flows:     parsedFlows,
			StartTime: cutoffTime,
			EndTime:   time.Now(),
			Count:     flowCount, // Count all flows, not unique connections
		}

		windows = append(windows, window)
	}

	return windows, nil
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
	// Clean up empty sorted sets for all key types
	patterns := []string{
		fmt.Sprintf("%s*", FlowKeyPrefix),
		fmt.Sprintf("%s*", WindowKeyPrefix),
		fmt.Sprintf("%s*", VerdictKeyPrefix),
		fmt.Sprintf("%s*", FlagsKeyPrefix),
	}

	for _, pattern := range patterns {
		keys, err := fc.client.Keys(fc.ctx, pattern).Result()
		if err != nil {
			fc.logger.Errorf("Failed to get keys for cleanup: %v", err)
			continue
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
}

// Close closes the FlowCache and cleans up resources
func (fc *FlowCache) Close() error {
	fc.cancel()
	close(fc.flowBuffer)
	return fc.client.Close()
}

// GetStats function removed - not needed anymore
