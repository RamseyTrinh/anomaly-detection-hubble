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

// storeFlow stores a single flow in Redis using simplified ZSET format
func (fc *FlowCache) storeFlow(flow *Flow) {
	if flow == nil {
		return
	}

	// Get timestamp
	timestamp := time.Now().Unix()
	if flow.Time != nil {
		timestamp = flow.Time.Unix()
	}

	// Extract flow information
	srcIP := "unknown"
	dstIP := "unknown"
	srcNamespace := "unknown"
	dstNamespace := "unknown"
	dstPort := "0"

	// Get source IP
	if flow.IP != nil {
		srcIP = flow.IP.Source
		dstIP = flow.IP.Destination
	}

	// Get source namespace
	if flow.Source != nil && flow.Source.Namespace != "" {
		srcNamespace = flow.Source.Namespace
	}

	// Get destination namespace and port
	if flow.Destination != nil && flow.Destination.Namespace != "" {
		dstNamespace = flow.Destination.Namespace
	}

	// Get destination port
	if flow.L4 != nil {
		if flow.L4.TCP != nil {
			dstPort = fmt.Sprintf("%d", flow.L4.TCP.DestinationPort)
		} else if flow.L4.UDP != nil {
			dstPort = fmt.Sprintf("%d", flow.L4.UDP.DestinationPort)
		}
	}

	// Create simplified flow member: srcIP|dstIP|srcNS|dstNS|dstPort
	flowMember := fmt.Sprintf("%s|%s|%s|%s|%s",
		srcIP, dstIP, srcNamespace, dstNamespace, dstPort)

	// Store in single ZSET with key "flows"
	err := fc.client.ZAdd(fc.ctx, "flows", &redis.Z{
		Score:  float64(timestamp),
		Member: flowMember,
	}).Err()
	if err != nil {
		fc.logger.Errorf("Failed to store flow in Redis: %v", err)
		return
	}

	// Set TTL for the flows key (expire after 60 seconds)
	fc.client.Expire(fc.ctx, "flows", 60*time.Second)

}

// parseFlowMember parses a flow member string back to components
func (fc *FlowCache) parseFlowMember(member string) (srcIP, dstIP, srcNS, dstNS, dstPort string) {
	parts := strings.Split(member, "|")
	if len(parts) >= 5 {
		return parts[0], parts[1], parts[2], parts[3], parts[4]
	}
	return "unknown", "unknown", "unknown", "unknown", "0"
}

// GetFlowWindows gets flow windows from the simplified Redis storage
func (fc *FlowCache) GetFlowWindows(windowSizeSeconds int64) ([]*FlowWindow, error) {
	// Get current timestamp and calculate window start
	now := time.Now().Unix()
	windowStart := now - windowSizeSeconds

	// Get flows from the last window using ZRANGEBYSCORE
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Group flows by source-destination pairs
	flowGroups := make(map[string]*FlowWindow)

	for _, flow := range flows {
		// Parse flow member
		srcIP, dstIP, srcNS, dstNS, dstPort := fc.parseFlowMember(flow.Member.(string))

		// Create group key
		groupKey := fmt.Sprintf("%s:%s->%s:%s:%s", srcNS, srcIP, dstNS, dstIP, dstPort)

		if _, exists := flowGroups[groupKey]; !exists {
			flowGroups[groupKey] = &FlowWindow{
				Key:       groupKey,
				Flows:     []Flow{},
				StartTime: time.Unix(windowStart, 0),
				EndTime:   time.Unix(now, 0),
				Count:     0,
			}
		}

		// Increment count
		flowGroups[groupKey].Count++
	}

	// Convert map to slice
	var windows []*FlowWindow
	for _, window := range flowGroups {
		windows = append(windows, window)
	}

	return windows, nil
}

// GetFlowMetrics retrieves aggregated metrics for a specific flow group
func (fc *FlowCache) GetFlowMetrics(groupKey string, windowDuration int64) (*FlowMetrics, error) {
	// Get current timestamp and calculate window start
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the last window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Count flows for this group
	var totalFlows int64
	var totalBytes int64
	var errorCount int64
	var connectionCount int64

	for _, flow := range flows {
		// Parse flow member
		srcIP, dstIP, srcNS, dstNS, dstPort := fc.parseFlowMember(flow.Member.(string))

		// Create flow key for comparison
		flowKey := fmt.Sprintf("%s:%s->%s:%s:%s", srcNS, srcIP, dstNS, dstIP, dstPort)

		if flowKey == groupKey {
			totalFlows++
			// Estimate bytes (simplified)
			totalBytes += 1024

			// Count connections (simplified - every flow is a connection)
			connectionCount++
		}
	}

	// Calculate rates
	flowRate := float64(totalFlows) / float64(windowDuration)
	byteRate := float64(totalBytes) / float64(windowDuration)
	errorRate := float64(errorCount) / float64(totalFlows) * 100
	if totalFlows == 0 {
		errorRate = 0
	}

	return &FlowMetrics{
		Key:             groupKey,
		TotalFlows:      totalFlows,
		TotalBytes:      totalBytes,
		ErrorCount:      errorCount,
		ConnectionCount: connectionCount,
		AverageLatency:  0, // Not available in simplified format
		ErrorRate:       errorRate,
		ByteRate:        byteRate,
		FlowRate:        flowRate,
		LastUpdated:     time.Now(),
		WindowDuration:  windowDuration,
	}, nil
}

// GetUniquePortsForSource gets unique destination ports for a source in time window
func (fc *FlowCache) GetUniquePortsForSource(sourceKey string, windowDuration int64) ([]string, error) {
	// Get current timestamp and calculate window start
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the last window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Extract unique ports for this source
	uniquePorts := make(map[string]bool)

	for _, flow := range flows {
		// Parse flow member
		srcIP, _, srcNS, _, dstPort := fc.parseFlowMember(flow.Member.(string))

		// Create source key for comparison
		flowSourceKey := fmt.Sprintf("%s:%s", srcNS, srcIP)

		if flowSourceKey == sourceKey {
			uniquePorts[dstPort] = true
		}
	}

	// Convert map to slice
	var ports []string
	for port := range uniquePorts {
		ports = append(ports, port)
	}

	return ports, nil
}

// GetPodNamespaces gets namespace information for source and destination pods
func (fc *FlowCache) GetPodNamespaces(srcPod, dstPod string) (srcNamespace, dstNamespace string, err error) {
	// Get current timestamp and calculate window start (last 60 seconds)
	now := time.Now().Unix()
	windowStart := now - 60

	// Get flows from the last 60 seconds
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return "", "", fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Look for flows involving these pods
	for _, flow := range flows {
		// Parse flow member
		srcIP, dstIP, srcNS, dstNS, _ := fc.parseFlowMember(flow.Member.(string))

		// Check if this flow involves the source pod
		if srcIP == srcPod {
			srcNamespace = srcNS
		}

		// Check if this flow involves the destination pod
		if dstIP == dstPod {
			dstNamespace = dstNS
		}

		// If we found both, we can return
		if srcNamespace != "" && dstNamespace != "" {
			break
		}
	}

	return srcNamespace, dstNamespace, nil
}

// GetFlowCountBySrcIP gets flow count for a specific source IP in time window
func (fc *FlowCache) GetFlowCountBySrcIP(srcIP string, windowDuration int64) (int64, error) {
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the time window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Count flows for this source IP
	var count int64
	for _, flow := range flows {
		parsedSrcIP, _, _, _, _ := fc.parseFlowMember(flow.Member.(string))
		if parsedSrcIP == srcIP {
			count++
		}
	}

	return count, nil
}

// GetFlowCountByDstIP gets flow count for a specific destination IP in time window
func (fc *FlowCache) GetFlowCountByDstIP(dstIP string, windowDuration int64) (int64, error) {
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the time window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Count flows for this destination IP
	var count int64
	for _, flow := range flows {
		_, parsedDstIP, _, _, _ := fc.parseFlowMember(flow.Member.(string))
		if parsedDstIP == dstIP {
			count++
		}
	}

	return count, nil
}

// GetFlowCountByDstNamespace gets flow count for a specific destination namespace in time window
func (fc *FlowCache) GetFlowCountByDstNamespace(dstNamespace string, windowDuration int64) (int64, error) {
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the time window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Count flows for this destination namespace
	var count int64
	for _, flow := range flows {
		_, _, _, parsedDstNS, _ := fc.parseFlowMember(flow.Member.(string))
		if parsedDstNS == dstNamespace {
			count++
		}
	}

	return count, nil
}

// GetUniquePortsBySrcIP gets unique destination ports for a source IP in time window
func (fc *FlowCache) GetUniquePortsBySrcIP(srcIP string, windowDuration int64) ([]string, error) {
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the time window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	// Extract unique ports for this source IP
	uniquePorts := make(map[string]bool)
	for _, flow := range flows {
		parsedSrcIP, _, _, _, dstPort := fc.parseFlowMember(flow.Member.(string))
		if parsedSrcIP == srcIP {
			uniquePorts[dstPort] = true
		}
	}

	// Convert map to slice
	var ports []string
	for port := range uniquePorts {
		ports = append(ports, port)
	}

	return ports, nil
}

// GetCrossNamespaceFlows gets flows with different source and destination namespaces
func (fc *FlowCache) GetCrossNamespaceFlows(windowDuration int64) ([]CrossNamespaceFlow, error) {
	now := time.Now().Unix()
	windowStart := now - windowDuration

	// Get flows from the time window
	flows, err := fc.client.ZRangeByScoreWithScores(fc.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get flows from Redis: %v", err)
	}

	var crossNamespaceFlows []CrossNamespaceFlow
	for _, flow := range flows {
		srcIP, dstIP, srcNS, dstNS, dstPort := fc.parseFlowMember(flow.Member.(string))

		// Check if this is cross-namespace traffic
		if srcNS != dstNS && srcNS != "unknown" && dstNS != "unknown" {
			crossNamespaceFlows = append(crossNamespaceFlows, CrossNamespaceFlow{
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcNS:     srcNS,
				DstNS:     dstNS,
				DstPort:   dstPort,
				Timestamp: time.Unix(int64(flow.Score), 0),
			})
		}
	}

	return crossNamespaceFlows, nil
}

// CrossNamespaceFlow represents a flow between different namespaces
type CrossNamespaceFlow struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcNS     string    `json:"src_namespace"`
	DstNS     string    `json:"dst_namespace"`
	DstPort   string    `json:"dst_port"`
	Timestamp time.Time `json:"timestamp"`
}

// Close closes the flow cache and cleans up resources
func (fc *FlowCache) Close() error {
	fc.cancel()
	return fc.client.Close()
}
