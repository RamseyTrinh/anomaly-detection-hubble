package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RuleEngine processes flow data from Redis and detects anomalies
type RuleEngine struct {
	flowCache     *FlowCache
	logger        *logrus.Logger
	alertChannel  chan Alert
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	lastStatusLog time.Time

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

// initializeDefaultRules sets up new anomaly detection rules
func (re *RuleEngine) initializeDefaultRules() {
	// 1. DDoS Spike Rule: >50 flows trong 5s
	re.rules["ddos_spike"] = &RuleConfig{
		Name:        "DDoS Spike",
		Enabled:     true,
		WindowSize:  5,    // 5 seconds
		Threshold:   50.0, // 50 flows
		Severity:    "CRITICAL",
		Description: "Detects DDoS attacks with >50 flows in 5 seconds",
	}

	// 2. Traffic Drop Rule: 30s không có traffic
	re.rules["traffic_drop"] = &RuleConfig{
		Name:        "Traffic Drop",
		Enabled:     true,
		WindowSize:  30,  // 30 seconds
		Threshold:   0.0, // 0 flows (no traffic)
		Severity:    "CRITICAL",
		Description: "Detects service down - no traffic for 30 seconds",
	}

	// 3. Port Scan Rule: >20 unique ports trong 30s
	re.rules["port_scan"] = &RuleConfig{
		Name:        "Port Scan",
		Enabled:     true,
		WindowSize:  30,   // 30 seconds
		Threshold:   20.0, // 20 unique ports
		Severity:    "HIGH",
		Description: "Detects port scanning - >20 unique ports in 30 seconds",
	}

	// 4. Cross-Namespace Rule: traffic sang namespace khác
	re.rules["cross_namespace"] = &RuleConfig{
		Name:        "Cross-Namespace",
		Enabled:     true,
		WindowSize:  60,  // 60 seconds
		Threshold:   1.0, // Any cross-namespace traffic
		Severity:    "MEDIUM",
		Description: "Detects cross-namespace traffic not in allow-list",
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
	ticker := time.NewTicker(5 * time.Second) // Evaluate every 5 seconds (faster for testing)
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

	// Get flow windows for status display
	windows, err := re.flowCache.GetFlowWindows(60) // 60 second window
	if err != nil {
		re.logger.Errorf("Failed to get flow windows: %v", err)
		return
	}

	// Calculate total requests across all windows
	totalRequests := 0
	for _, window := range windows {
		totalRequests += window.Count
	}

	// Display status every 60 seconds
	if time.Since(re.lastStatusLog) > 60*time.Second {
		re.logger.Infof("📊 Status: %d total requests in last 60s - Normal", totalRequests)
		re.lastStatusLog = time.Now()
	}

	// Hiển thị thông tin về baseline nếu cần
	if len(windows) > 0 {
		re.logger.Debugf("📈 Analyzing %d flow windows for anomaly detection", len(windows))

		// Debug: In chi tiết các flow windows
		for i, window := range windows {
			re.logger.Debugf("   Window %d: %s (%d flows)", i+1, window.Key, window.Count)
		}
	}

	enabledCount := 0
	alertCount := 0
	for ruleName, config := range re.rules {
		if !config.Enabled {
			continue
		}
		enabledCount++
		if re.evaluateRule(ruleName, config) {
			alertCount++
		}
	}

	if alertCount > 0 {
		re.logger.Warnf("🚨 %d anomalies detected out of %d rules", alertCount, enabledCount)
	}
}

// evaluateRule evaluates a specific rule and returns true if any alerts were triggered
func (re *RuleEngine) evaluateRule(ruleName string, config *RuleConfig) bool {
	// Get flow windows from Redis
	windows, err := re.flowCache.GetFlowWindows(config.WindowSize)
	if err != nil {
		re.logger.Errorf("Failed to get flow windows for rule %s: %v", ruleName, err)
		return false
	}

	alertTriggered := false
	// Evaluate rule for each window
	for _, window := range windows {
		result := re.runRule(ruleName, config, window)
		if result.Triggered {
			re.handleRuleResult(result)
			alertTriggered = true
		}
	}

	return alertTriggered
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
	case "ddos_spike":
		result = re.checkDDoSSpike(config, metrics, result)
	case "traffic_drop":
		result = re.checkTrafficDrop(config, metrics, result)
	case "port_scan":
		result = re.checkPortScan(config, metrics, result)
	case "cross_namespace":
		result = re.checkCrossNamespace(config, metrics, result)
	default:
		re.logger.Warnf("Unknown rule: %s", ruleName)
	}

	return result
}

// checkDDoSSpike checks for DDoS attacks with >50 flows in 5 seconds
func (re *RuleEngine) checkDDoSSpike(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	if metrics.TotalFlows > int64(config.Threshold) {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("DDoS Attack Detected: %d flows in %ds (threshold: %.0f) - %s",
			metrics.TotalFlows, config.WindowSize, config.Threshold, metrics.Key)
		result.Details["total_flows"] = metrics.TotalFlows
		result.Details["window_duration"] = config.WindowSize
		result.Details["threshold"] = config.Threshold
	}
	return result
}

// checkTrafficDrop checks for service down - no traffic for 30 seconds
func (re *RuleEngine) checkTrafficDrop(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	if metrics.TotalFlows == 0 {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("Service Down Detected: No traffic for %ds - %s",
			config.WindowSize, metrics.Key)
		result.Details["total_flows"] = metrics.TotalFlows
		result.Details["window_duration"] = config.WindowSize
		result.Details["service_status"] = "DOWN"
	}
	return result
}

// checkPortScan checks for port scanning - >20 unique ports in 30 seconds
func (re *RuleEngine) checkPortScan(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	// Get unique ports for this source in the time window
	uniquePorts, err := re.flowCache.GetUniquePortsForSource(metrics.Key, config.WindowSize)
	if err != nil {
		re.logger.Errorf("Failed to get unique ports for port scan check: %v", err)
		return result
	}

	if len(uniquePorts) > int(config.Threshold) {
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("Port Scan Detected: %d unique ports in %ds (threshold: %.0f) - %s",
			len(uniquePorts), config.WindowSize, config.Threshold, metrics.Key)
		result.Details["unique_ports"] = len(uniquePorts)
		result.Details["window_duration"] = config.WindowSize
		result.Details["threshold"] = config.Threshold
		result.Details["ports"] = uniquePorts
	}
	return result
}

// checkCrossNamespace checks for cross-namespace traffic not in allow-list
func (re *RuleEngine) checkCrossNamespace(config *RuleConfig, metrics *FlowMetrics, result *RuleResult) *RuleResult {
	// Extract namespace information from the key
	// Key format: flow:srcPod:dstPod
	keyParts := strings.Split(metrics.Key, ":")
	if len(keyParts) < 3 {
		re.logger.Warnf("Invalid flow key format for cross-namespace check: %s", metrics.Key)
		return result
	}

	srcPod := keyParts[1]
	dstPod := keyParts[2]

	// Get namespace information for source and destination pods
	srcNamespace, dstNamespace, err := re.flowCache.GetPodNamespaces(srcPod, dstPod)
	if err != nil {
		re.logger.Errorf("Failed to get pod namespaces: %v", err)
		return result
	}

	// Check if this is cross-namespace traffic
	if srcNamespace != dstNamespace {
		// Check if this cross-namespace traffic is allowed
		if !re.isCrossNamespaceAllowed(srcNamespace, dstNamespace) {
			result.Triggered = true
			result.Severity = config.Severity
			result.Message = fmt.Sprintf("Cross-Namespace Traffic Detected: %s (%s) -> %s (%s) - %s",
				srcPod, srcNamespace, dstPod, dstNamespace, metrics.Key)
			result.Details["src_pod"] = srcPod
			result.Details["src_namespace"] = srcNamespace
			result.Details["dst_pod"] = dstPod
			result.Details["dst_namespace"] = dstNamespace
			result.Details["traffic_type"] = "CROSS_NAMESPACE"
		}
	}
	return result
}

// isCrossNamespaceAllowed checks if cross-namespace traffic is allowed
func (re *RuleEngine) isCrossNamespaceAllowed(srcNamespace, dstNamespace string) bool {
	// Define allowed cross-namespace traffic patterns
	allowedPatterns := map[string][]string{
		"default":     {"kube-system", "monitoring"}, // default can talk to kube-system and monitoring
		"kube-system": {"default"},                   // kube-system can talk to default
		"monitoring":  {"default"},                   // monitoring can talk to default
	}

	allowedDstNamespaces, exists := allowedPatterns[srcNamespace]
	if !exists {
		return false // No cross-namespace traffic allowed from this namespace
	}

	for _, allowed := range allowedDstNamespaces {
		if allowed == dstNamespace {
			return true
		}
	}
	return false
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
	timestamp := alert.Timestamp.Format("2006-01-02 15:04:05")

	// Format severity with emoji
	severityEmoji := "⚠️"
	switch alert.Severity {
	case "CRITICAL":
		severityEmoji = "🚨"
	case "HIGH":
		severityEmoji = "🔴"
	case "MEDIUM":
		severityEmoji = "🟡"
	case "LOW":
		severityEmoji = "🟢"
	}

	// Display alert with clear formatting
	re.logger.Warnf("%s [%s] %s %s", severityEmoji, timestamp, alert.Severity, alert.Message)

	if alert.Stats != nil {
		re.logger.Warnf("   📈 Stats: %d flows, %.2f flow/sec, %d connections",
			alert.Stats.TotalFlows, alert.Stats.FlowRate, alert.Stats.TotalConnections)
	}

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
