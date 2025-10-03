package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
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
	// 1. DDoS Spike Rule: >20 flows trong 10s
	re.rules["ddos_spike"] = &RuleConfig{
		Name:        "DDoS Spike",
		Enabled:     true,
		WindowSize:  10,   // 10 seconds
		Threshold:   20.0, // 20 flows (giảm từ 50 xuống 20)
		Severity:    "CRITICAL",
		Description: "Detects DDoS attacks with >20 flows in 10 seconds",
	}

	// 2. Traffic Drop Rule: 30s không có traffic
	// re.rules["traffic_drop"] = &RuleConfig{
	// 	Name:        "Traffic Drop",
	// 	Enabled:     true,
	// 	WindowSize:  30,  // 30 seconds
	// 	Threshold:   0.0, // 0 flows (no traffic)
	// 	Severity:    "CRITICAL",
	// 	Description: "Detects service down - no traffic for 30 seconds",
	// }

	// // 3. Port Scan Rule: >20 unique ports trong 30s
	// re.rules["port_scan"] = &RuleConfig{
	// 	Name:        "Port Scan",
	// 	Enabled:     true,
	// 	WindowSize:  30,   // 30 seconds
	// 	Threshold:   20.0, // 20 unique ports
	// 	Severity:    "HIGH",
	// 	Description: "Detects port scanning - >20 unique ports in 30 seconds",
	// }

	// // 4. Cross-Namespace Rule: traffic sang namespace khác
	// re.rules["cross_namespace"] = &RuleConfig{
	// 	Name:        "Cross-Namespace",
	// 	Enabled:     true,
	// 	WindowSize:  60,  // 60 seconds
	// 	Threshold:   1.0, // Any cross-namespace traffic
	// 	Severity:    "MEDIUM",
	// 	Description: "Detects cross-namespace traffic not in allow-list",
	// }
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

func (re *RuleEngine) evaluateAllRules() {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if time.Since(re.lastStatusLog) > 60*time.Second {
		re.logger.Infof("Status: Evaluating anomaly detection rules - Normal")
		re.lastStatusLog = time.Now()

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
	// Evaluate rule directly without flow windows
	result := re.runRuleDirect(ruleName, config)
	if result.Triggered {
		re.handleRuleResult(result)
		return true
	}
	return false
}

// runRuleDirect executes a specific rule directly against Redis data
func (re *RuleEngine) runRuleDirect(ruleName string, config *RuleConfig) *RuleResult {
	result := &RuleResult{
		RuleName:  ruleName,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	switch ruleName {
	case "ddos_spike":
		result = re.checkDDoSSpikeDirect(config, result)
	// case "traffic_drop":
	// 	result = re.checkTrafficDropDirect(config, result)
	// case "port_scan":
	// 	result = re.checkPortScanDirect(config, result)
	// case "cross_namespace":
	// 	result = re.checkCrossNamespaceDirect(config, result)
	default:
		re.logger.Warnf("Unknown rule: %s", ruleName)
	}

	return result
}

// checkDDoSSpikeDirect checks for DDoS attacks using direct Redis queries
func (re *RuleEngine) checkDDoSSpikeDirect(config *RuleConfig, result *RuleResult) *RuleResult {
	// Get all flows from the time window
	now := time.Now().Unix()
	windowStart := now - config.WindowSize

	flows, err := re.flowCache.client.ZRangeByScoreWithScores(re.flowCache.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		re.logger.Errorf("Failed to get flows for DDoS detection: %v", err)
		return result
	}

	totalFlows := len(flows)
	// re.logger.Debugf("🔍 DDoS Detection: Found %d total flows in time window", totalFlows)

	if int64(totalFlows) > int64(config.Threshold) {
		re.logger.Warnf("🚨 DDoS Attack Detected: %d total flows in %ds (threshold: %.0f)",
			totalFlows, config.WindowSize, config.Threshold)
		result.Triggered = true
		result.Severity = config.Severity
		result.Message = fmt.Sprintf("DDoS Attack Detected: %d total flows in %ds (threshold: %.0f)",
			totalFlows, config.WindowSize, config.Threshold)
		result.Details["total_flows"] = totalFlows
		result.Details["window_duration"] = config.WindowSize
		result.Details["threshold"] = config.Threshold
		return result
	}

	// Also check per source IP for detailed analysis
	srcIPCounts := make(map[string]int64)
	for _, flow := range flows {
		srcIP, _, _, _, _ := re.flowCache.parseFlowMember(flow.Member.(string))
		if srcIP != "unknown" {
			srcIPCounts[srcIP]++
		}
	}

	return result
}

// checkTrafficDropDirect checks for service down using direct Redis queries
func (re *RuleEngine) checkTrafficDropDirect(config *RuleConfig, result *RuleResult) *RuleResult {
	// Get all unique destination IPs and namespaces from the time window
	now := time.Now().Unix()
	windowStart := now - config.WindowSize

	flows, err := re.flowCache.client.ZRangeByScoreWithScores(re.flowCache.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		re.logger.Errorf("Failed to get flows for traffic drop detection: %v", err)
		return result
	}

	// Count flows per destination IP and namespace
	dstIPCounts := make(map[string]int64)
	dstNSCounts := make(map[string]int64)

	for _, flow := range flows {
		_, dstIP, _, dstNS, _ := re.flowCache.parseFlowMember(flow.Member.(string))
		if dstIP != "unknown" {
			dstIPCounts[dstIP]++
		}
		if dstNS != "unknown" {
			dstNSCounts[dstNS]++
		}
	}

	// Check for services with no traffic
	for dstIP, count := range dstIPCounts {
		if count == 0 {
			result.Triggered = true
			result.Severity = config.Severity
			result.Message = fmt.Sprintf("Service Down Detected: No traffic to %s for %ds",
				dstIP, config.WindowSize)
			result.Details["dst_ip"] = dstIP
			result.Details["total_flows"] = count
			result.Details["window_duration"] = config.WindowSize
			result.Details["service_status"] = "DOWN"
			break
		}
	}

	// Also check namespaces
	for dstNS, count := range dstNSCounts {
		if count == 0 {
			result.Triggered = true
			result.Severity = config.Severity
			result.Message = fmt.Sprintf("Namespace Down Detected: No traffic to %s namespace for %ds",
				dstNS, config.WindowSize)
			result.Details["dst_namespace"] = dstNS
			result.Details["total_flows"] = count
			result.Details["window_duration"] = config.WindowSize
			result.Details["service_status"] = "DOWN"
			break
		}
	}

	return result
}

// checkPortScanDirect checks for port scanning using direct Redis queries
func (re *RuleEngine) checkPortScanDirect(config *RuleConfig, result *RuleResult) *RuleResult {
	// Get all unique source IPs from the time window
	now := time.Now().Unix()
	windowStart := now - config.WindowSize

	flows, err := re.flowCache.client.ZRangeByScoreWithScores(re.flowCache.ctx, "flows", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", windowStart),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		re.logger.Errorf("Failed to get flows for port scan detection: %v", err)
		return result
	}

	// Group flows by source IP and count unique destination ports
	srcIPPorts := make(map[string]map[string]bool)
	for _, flow := range flows {
		srcIP, _, _, _, dstPort := re.flowCache.parseFlowMember(flow.Member.(string))
		if srcIP != "unknown" && dstPort != "0" {
			if srcIPPorts[srcIP] == nil {
				srcIPPorts[srcIP] = make(map[string]bool)
			}
			srcIPPorts[srcIP][dstPort] = true
		}
	}

	// Check each source IP for port scan threshold
	for srcIP, ports := range srcIPPorts {
		uniquePortCount := len(ports)
		if uniquePortCount > int(config.Threshold) {
			result.Triggered = true
			result.Severity = config.Severity
			result.Message = fmt.Sprintf("Port Scan Detected: %d unique ports from %s in %ds (threshold: %.0f)",
				uniquePortCount, srcIP, config.WindowSize, config.Threshold)

			// Convert map to slice for details
			var portList []string
			for port := range ports {
				portList = append(portList, port)
			}

			result.Details["src_ip"] = srcIP
			result.Details["unique_ports"] = uniquePortCount
			result.Details["window_duration"] = config.WindowSize
			result.Details["threshold"] = config.Threshold
			result.Details["ports"] = portList
			break // Alert on first detected port scan
		}
	}

	return result
}

// checkCrossNamespaceDirect checks for cross-namespace traffic using direct Redis queries
func (re *RuleEngine) checkCrossNamespaceDirect(config *RuleConfig, result *RuleResult) *RuleResult {
	// Get cross-namespace flows from the time window
	crossNamespaceFlows, err := re.flowCache.GetCrossNamespaceFlows(config.WindowSize)
	if err != nil {
		re.logger.Errorf("Failed to get cross-namespace flows: %v", err)
		return result
	}

	// Check each cross-namespace flow against allow-list
	for _, flow := range crossNamespaceFlows {
		if !re.isCrossNamespaceAllowed(flow.SrcNS, flow.DstNS) {
			result.Triggered = true
			result.Severity = config.Severity
			result.Message = fmt.Sprintf("Cross-Namespace Traffic Detected: %s (%s) -> %s (%s) on port %s",
				flow.SrcIP, flow.SrcNS, flow.DstIP, flow.DstNS, flow.DstPort)
			result.Details["src_ip"] = flow.SrcIP
			result.Details["src_namespace"] = flow.SrcNS
			result.Details["dst_ip"] = flow.DstIP
			result.Details["dst_namespace"] = flow.DstNS
			result.Details["dst_port"] = flow.DstPort
			result.Details["timestamp"] = flow.Timestamp
			result.Details["traffic_type"] = "CROSS_NAMESPACE"
			break // Alert on first detected cross-namespace violation
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
			TotalFlows:       0, // Not available in simplified detection
			TotalBytes:       0, // Not available in simplified detection
			TotalConnections: 0, // Not available in simplified detection
			DroppedPackets:   0, // Not available in simplified detection
			FlowRate:         0, // Not available in simplified detection
			ByteRate:         0, // Not available in simplified detection
			ConnectionRate:   0, // Not available in simplified detection
			DropRate:         0, // Not available in simplified detection
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

func (re *RuleEngine) GetAlertChannel() <-chan Alert {
	return re.alertChannel
}

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
