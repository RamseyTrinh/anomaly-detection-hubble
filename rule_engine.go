package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RuleEngine processes flow data from Redis and detects anomalies
type RuleEngine struct {
	flowCache    *FlowCache
	logger       *logrus.Logger
	alertChannel chan Alert
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex

	// Rule configurations
	rules map[string]*RuleConfig
}

// RuleConfig defines configuration for anomaly detection rules
type RuleConfig struct {
	Name        string  `json:"name"`
	Enabled     bool    `json:"enabled"`
	WindowSize  int64   `json:"window_size_seconds"`
	Threshold   float64 `json:"threshold"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// RuleResult represents the result of a rule evaluation
type RuleResult struct {
	RuleName  string                 `json:"rule_name"`
	Triggered bool                   `json:"triggered"`
	Severity  string                 `json:"severity"`
	Message   string                 `json:"message"`
	Metrics   *FlowMetrics           `json:"metrics"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(flowCache *FlowCache, logger *logrus.Logger) *RuleEngine {
	ctx, cancel := context.WithCancel(context.Background())

	re := &RuleEngine{
		flowCache:    flowCache,
		logger:       logger,
		alertChannel: make(chan Alert, 100),
		ctx:          ctx,
		cancel:       cancel,
		rules:        make(map[string]*RuleConfig),
	}

	// Initialize default rules
	re.initializeDefaultRules()

	return re
}

// initializeDefaultRules sets up default anomaly detection rules
func (re *RuleEngine) initializeDefaultRules() {
	re.rules["high_error_rate"] = &RuleConfig{
		Name:        "High Error Rate",
		Enabled:     true,
		WindowSize:  60,  // 1 minute
		Threshold:   5.0, // 5%
		Severity:    "HIGH",
		Description: "Detects when error rate exceeds threshold",
	}

	re.rules["traffic_spike"] = &RuleConfig{
		Name:        "Traffic Spike",
		Enabled:     true,
		WindowSize:  300,   // 5 minutes
		Threshold:   200.0, // 200% increase
		Severity:    "HIGH",
		Description: "Detects sudden traffic spikes",
	}

	re.rules["connection_flood"] = &RuleConfig{
		Name:        "Connection Flood",
		Enabled:     true,
		WindowSize:  10,    // 10 seconds
		Threshold:   100.0, // 100 connections
		Severity:    "CRITICAL",
		Description: "Detects DDoS-like connection floods",
	}

	re.rules["error_burst"] = &RuleConfig{
		Name:        "Error Burst",
		Enabled:     true,
		WindowSize:  30,   // 30 seconds
		Threshold:   10.0, // 10 errors
		Severity:    "HIGH",
		Description: "Detects error bursts in short time windows",
	}

}

// Start begins the rule engine processing
func (re *RuleEngine) Start() {
	re.logger.Info("Starting Rule Engine")

	// Start periodic rule evaluation
	go re.periodicEvaluation()

	// Start alert processor
	go re.alertProcessor()
}

// Stop stops the rule engine
func (re *RuleEngine) Stop() {
	re.logger.Info("Stopping Rule Engine")
	re.cancel()
	close(re.alertChannel)
}

// periodicEvaluation runs rule evaluation periodically
func (re *RuleEngine) periodicEvaluation() {
	ticker := time.NewTicker(10 * time.Second) // Evaluate every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			re.evaluateAllRules()
		case <-re.ctx.Done():
			return
		}
	}
}

// evaluateAllRules evaluates all enabled rules
func (re *RuleEngine) evaluateAllRules() {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for ruleName, config := range re.rules {
		if !config.Enabled {
			continue
		}

		re.evaluateRule(ruleName, config)
	}
}

// evaluateRule evaluates a specific rule
func (re *RuleEngine) evaluateRule(ruleName string, config *RuleConfig) {
	// Get flow windows from Redis
	windows, err := re.flowCache.GetFlowWindows(config.WindowSize)
	if err != nil {
		re.logger.Errorf("Failed to get flow windows for rule %s: %v", ruleName, err)
		return
	}

	// Evaluate rule for each window
	for _, window := range windows {
		result := re.runRule(ruleName, config, window)
		if result.Triggered {
			re.handleRuleResult(result)
		}
	}
}

// runRule executes a specific rule against a flow window
func (re *RuleEngine) runRule(ruleName string, config *RuleConfig, window *FlowWindow) *RuleResult {
	result := &RuleResult{
		RuleName:  ruleName,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get metrics for this window
	metrics, err := re.flowCache.GetFlowMetrics(window.Key, config.WindowSize)
	if err != nil {
		re.logger.Errorf("Failed to get metrics for rule %s: %v", ruleName, err)
		return result
	}

	result.Metrics = metrics

	switch ruleName {
	case "high_error_rate":
		result = re.checkHighErrorRate(config, metrics, result)
	case "traffic_spike":
		result = re.checkTrafficSpike(config, metrics, result)
	case "connection_flood":
		result = re.checkConnectionFlood(config, metrics, result)
	case "error_burst":
		result = re.checkErrorBurst(config, metrics, result)
	default:
		re.logger.Warnf("Unknown rule: %s", ruleName)
	}

	return result
}

// checkHighErrorRate checks for high error rates
func (re *RuleEngine) checkHighErrorRate(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	if metrics.ErrorRate > config.Threshold {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("High error rate detected: %.2f%% error rate (threshold: %.2f%%) for %s",
			metrics.ErrorRate, config.Threshold, metrics.Key)
		result.Details["error_rate"] = metrics.ErrorRate
		result.Details["error_count"] = metrics.ErrorCount
		result.Details["total_flows"] = metrics.TotalFlows
	}
	return result
}

// checkTrafficSpike checks for traffic spikes
func (re *RuleEngine) checkTrafficSpike(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	// This is a simplified check - in practice you'd compare with historical baseline
	// For now, we'll check if byte rate is unusually high
	if metrics.ByteRate > config.Threshold {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("Traffic spike detected: %.2f bytes/sec (threshold: %.2f) for %s",
			metrics.ByteRate, config.Threshold, metrics.Key)
		result.Details["byte_rate"] = metrics.ByteRate
		result.Details["total_bytes"] = metrics.TotalBytes
		result.Details["flow_rate"] = metrics.FlowRate
	}
	return result
}

// checkConnectionFlood checks for connection floods (DDoS patterns)
func (re *RuleEngine) checkConnectionFlood(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	if metrics.ConnectionCount > int64(config.Threshold) {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("Connection flood detected: %d connections (threshold: %.0f) for %s",
			metrics.ConnectionCount, config.Threshold, metrics.Key)
		result.Details["connection_count"] = metrics.ConnectionCount
		result.Details["connection_rate"] = float64(metrics.ConnectionCount) / float64(config.WindowSize)
	}
	return result
}

// checkErrorBurst checks for error bursts
func (re *RuleEngine) checkErrorBurst(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	if metrics.ErrorCount > int64(config.Threshold) {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("Error burst detected: %d errors (threshold: %.0f) in %d seconds for %s",
			metrics.ErrorCount, config.Threshold, config.WindowSize, metrics.Key)
		result.Details["error_count"] = metrics.ErrorCount
		result.Details["error_rate"] = metrics.ErrorRate
		result.Details["total_flows"] = metrics.TotalFlows
	}
	return result
}

// handleRuleResult processes a triggered rule result
func (re *RuleEngine) handleRuleResult(result *RuleResult) {
	// Create alert from rule result
	alert := Alert{
		Type:      result.RuleName,
		Severity:  result.Severity,
		Message:   result.Message,
		Timestamp: result.Timestamp,
		Stats: &FlowStats{
			TotalFlows:       result.Metrics.TotalFlows,
			TotalBytes:       result.Metrics.TotalBytes,
			TotalConnections: result.Metrics.ConnectionCount,
			DroppedPackets:   result.Metrics.ErrorCount,
			FlowRate:         result.Metrics.FlowRate,
			ByteRate:         result.Metrics.ByteRate,
			ConnectionRate:   float64(result.Metrics.ConnectionCount) / float64(result.Metrics.WindowDuration),
			DropRate:         result.Metrics.ErrorRate,
		},
	}

	// Send alert
	select {
	case re.alertChannel <- alert:
		re.logger.Infof("Alert sent for rule %s: %s", result.RuleName, result.Message)
	default:
		re.logger.Error("Alert channel is full, dropping alert")
	}
}

// alertProcessor processes alerts from the rule engine
func (re *RuleEngine) alertProcessor() {
	for {
		select {
		case alert := <-re.alertChannel:
			re.processAlert(alert)
		case <-re.ctx.Done():
			return
		}
	}
}

// processAlert handles an alert (for now, just logs it)
func (re *RuleEngine) processAlert(alert Alert) {
	re.logger.WithFields(logrus.Fields{
		"type":      alert.Type,
		"severity":  alert.Severity,
		"message":   alert.Message,
		"timestamp": alert.Timestamp,
	}).Warn("ANOMALY DETECTED")

	// Here you could integrate with external alerting systems
	// like Slack, PagerDuty, email, etc.
}

// GetAlertChannel returns the alert channel for external consumption
func (re *RuleEngine) GetAlertChannel() <-chan Alert {
	return re.alertChannel
}

// GetStats returns rule engine statistics
func (re *RuleEngine) GetStats() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_rules"] = len(re.rules)

	enabledCount := 0
	for _, config := range re.rules {
		if config.Enabled {
			enabledCount++
		}
	}
	stats["enabled_rules"] = enabledCount
	stats["disabled_rules"] = len(re.rules) - enabledCount

	return stats
}
