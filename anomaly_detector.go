package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AnomalyDetector handles anomaly detection logic
type AnomalyDetector struct {
	config       *Config
	logger       *logrus.Logger
	flowStats    *FlowStats
	alertChannel chan Alert
	mu           sync.RWMutex

	// Redis-based flow caching and rule engine
	flowCache  *FlowCache
	ruleEngine *RuleEngine

	// Legacy fields removed - using rule engine instead
}

// Legacy types removed - using rule engine instead

// NamespaceStats holds statistics for a specific namespace
type NamespaceStats struct {
	Namespace        string
	TotalFlows       int64
	TotalBytes       int64
	TotalConnections int64
	DroppedPackets   int64
	LastReset        time.Time
	FlowRate         float64
	ByteRate         float64
	ConnectionRate   float64
	DropRate         float64
}

// FlowStats holds statistics about network flows
type FlowStats struct {
	TotalFlows       int64
	TotalBytes       int64
	TotalConnections int64
	DroppedPackets   int64
	LastReset        time.Time
	FlowRate         float64
	ByteRate         float64
	ConnectionRate   float64
	DropRate         float64
}

// Alert represents an anomaly alert
type Alert struct {
	Type      string     `json:"type"`
	Severity  string     `json:"severity"`
	Message   string     `json:"message"`
	Timestamp time.Time  `json:"timestamp"`
	FlowData  *Flow      `json:"flow_data,omitempty"`
	Stats     *FlowStats `json:"stats,omitempty"`
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *Config, logger *logrus.Logger) (*AnomalyDetector, error) {
	// Initialize Redis-based flow cache
	flowCache, err := NewFlowCache(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow cache: %v", err)
	}

	// Initialize rule engine
	ruleEngine := NewRuleEngine(flowCache, logger)

	ad := &AnomalyDetector{
		config:       config,
		logger:       logger,
		flowStats:    &FlowStats{LastReset: time.Now()},
		alertChannel: make(chan Alert, 100),
		flowCache:    flowCache,
		ruleEngine:   ruleEngine,
	}

	// Start rule engine
	ruleEngine.Start()

	logger.Info("AnomalyDetector initialized with Redis-based flow caching")
	return ad, nil
}

// ProcessFlow processes a single flow and checks for anomalies
func (ad *AnomalyDetector) ProcessFlow(ctx context.Context, f *Flow) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Update statistics
	ad.updateStats(f)

	// Add flow to Redis cache for rule engine processing
	ad.flowCache.AddFlow(f)

	// Legacy anomaly detection removed - using rule engine instead
}

// updateStats updates flow statistics
func (ad *AnomalyDetector) updateStats(f *Flow) {
	ad.flowStats.TotalFlows++

	// Calculate bytes from flow
	bytes := ad.calculateBytes(f)
	ad.flowStats.TotalBytes += bytes

	// Check if it's a new connection
	if f.Type == FlowType_L3_L4 || f.Type == FlowType_L7 {
		ad.flowStats.TotalConnections++
	}

	// Check for dropped packets
	if f.Verdict == Verdict_DROPPED {
		ad.flowStats.DroppedPackets++
	}

	// Calculate rates
	now := time.Now()
	timeDiff := now.Sub(ad.flowStats.LastReset).Seconds()
	if timeDiff > 0 {
		ad.flowStats.FlowRate = float64(ad.flowStats.TotalFlows) / timeDiff
		ad.flowStats.ByteRate = float64(ad.flowStats.TotalBytes) / timeDiff
		ad.flowStats.ConnectionRate = float64(ad.flowStats.TotalConnections) / timeDiff
		ad.flowStats.DropRate = (float64(ad.flowStats.DroppedPackets) / float64(ad.flowStats.TotalFlows)) * 100
	}
}

// calculateBytes estimates bytes from flow data
func (ad *AnomalyDetector) calculateBytes(f *Flow) int64 {
	// This is a simplified calculation - in practice, you'd want more accurate byte counting
	if f.L4 != nil {
		if f.L4.TCP != nil {
			return int64(f.L4.TCP.Bytes)
		}
		if f.L4.UDP != nil {
			return int64(f.L4.UDP.Bytes)
		}
	}
	return 0
}

// Legacy detection functions removed - using rule engine instead

// sendAlert sends an alert to the alert channel
func (ad *AnomalyDetector) sendAlert(alert Alert) {
	select {
	case ad.alertChannel <- alert:
		// Alert sent successfully - will be printed by printAnomalyAlert function
	default:
		ad.logger.Error("Alert channel is full, dropping alert")
	}
}

// GetAlertChannel returns the alert channel
func (ad *AnomalyDetector) GetAlertChannel() <-chan Alert {
	return ad.alertChannel
}

// Close closes the anomaly detector and cleans up resources
func (ad *AnomalyDetector) Close() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Stop rule engine
	if ad.ruleEngine != nil {
		ad.ruleEngine.Stop()
	}

	// Close flow cache
	if ad.flowCache != nil {
		return ad.flowCache.Close()
	}

	return nil
}

// GetRedisStats returns Redis cache statistics
func (ad *AnomalyDetector) GetRedisStats() (map[string]interface{}, error) {
	if ad.flowCache == nil {
		return nil, fmt.Errorf("flow cache not initialized")
	}
	return ad.flowCache.GetStats()
}

// GetRuleEngineStats returns rule engine statistics
func (ad *AnomalyDetector) GetRuleEngineStats() map[string]interface{} {
	if ad.ruleEngine == nil {
		return nil
	}
	return ad.ruleEngine.GetStats()
}
