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
	config           *Config
	logger           *logrus.Logger
	flowStats        *FlowStats
	alertChannel     chan Alert
	mu               sync.RWMutex
	knownPorts       map[uint32]bool
	knownDests       map[string]bool
	unusualPorts     map[uint32]int
	unusualDests     map[string]int
	namespaceStats   map[string]*NamespaceStats
	unusualNamespace map[string]int
}

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
func NewAnomalyDetector(config *Config, logger *logrus.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		config:           config,
		logger:           logger,
		flowStats:        &FlowStats{LastReset: time.Now()},
		alertChannel:     make(chan Alert, 100),
		knownPorts:       make(map[uint32]bool),
		knownDests:       make(map[string]bool),
		unusualPorts:     make(map[uint32]int),
		unusualDests:     make(map[string]int),
		namespaceStats:   make(map[string]*NamespaceStats),
		unusualNamespace: make(map[string]int),
	}
}

// ProcessFlow processes a single flow and checks for anomalies
func (ad *AnomalyDetector) ProcessFlow(ctx context.Context, f *Flow) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Update statistics
	ad.updateStats(f)

	// Check for various anomalies
	ad.checkHighBandwidth(f)
	ad.checkUnusualPorts(f)
	ad.checkUnusualDestinations(f)
	ad.checkDroppedPackets(f)
	ad.checkHighConnectionRate(f)
	ad.checkNamespaceAnomalies(f)
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

	// Update namespace statistics
	ad.updateNamespaceStats(f, bytes)
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

// checkHighBandwidth checks for unusually high bandwidth usage
func (ad *AnomalyDetector) checkHighBandwidth(f *Flow) {
	if ad.flowStats.ByteRate > float64(ad.config.AlertThresholds.HighBandwidthThreshold) {
		alert := Alert{
			Type:     "HIGH_BANDWIDTH",
			Severity: "HIGH",
			Message: fmt.Sprintf("High bandwidth detected: %.2f bytes/s (threshold: %d)",
				ad.flowStats.ByteRate, ad.config.AlertThresholds.HighBandwidthThreshold),
			Timestamp: time.Now(),
			FlowData:  f,
			Stats:     ad.flowStats,
		}
		ad.sendAlert(alert)
	}
}

// checkUnusualPorts checks for connections to unusual ports
func (ad *AnomalyDetector) checkUnusualPorts(f *Flow) {
	if f.L4 != nil {
		var port uint32
		if f.L4.TCP != nil {
			port = f.L4.TCP.DestinationPort
		} else if f.L4.UDP != nil {
			port = f.L4.UDP.DestinationPort
		}

		if port > 0 {
			// Check if it's a known port (common services)
			if !ad.isKnownPort(port) {
				ad.unusualPorts[port]++
				if ad.unusualPorts[port] > ad.config.AlertThresholds.UnusualPortThreshold {
					alert := Alert{
						Type:     "UNUSUAL_PORT",
						Severity: "MEDIUM",
						Message: fmt.Sprintf("Unusual port activity detected: port %d (%d connections)",
							port, ad.unusualPorts[port]),
						Timestamp: time.Now(),
						FlowData:  f,
					}
					ad.sendAlert(alert)
				}
			}
		}
	}
}

// checkUnusualDestinations checks for connections to unusual destinations
func (ad *AnomalyDetector) checkUnusualDestinations(f *Flow) {
	if f.IP != nil {
		destIP := f.IP.Destination
		if destIP != "" {
			if !ad.isKnownDestination(destIP) {
				ad.unusualDests[destIP]++
				if ad.unusualDests[destIP] > ad.config.AlertThresholds.UnusualDestinationThreshold {
					alert := Alert{
						Type:     "UNUSUAL_DESTINATION",
						Severity: "HIGH",
						Message: fmt.Sprintf("Unusual destination activity detected: %s (%d connections)",
							destIP, ad.unusualDests[destIP]),
						Timestamp: time.Now(),
						FlowData:  f,
					}
					ad.sendAlert(alert)
				}
			}
		}
	}
}

// checkDroppedPackets checks for high packet drop rates
func (ad *AnomalyDetector) checkDroppedPackets(f *Flow) {
	if ad.flowStats.DropRate > ad.config.AlertThresholds.DropRateThreshold {
		alert := Alert{
			Type:     "HIGH_DROP_RATE",
			Severity: "HIGH",
			Message: fmt.Sprintf("High packet drop rate detected: %.2f%% (threshold: %.2f%%)",
				ad.flowStats.DropRate, ad.config.AlertThresholds.DropRateThreshold),
			Timestamp: time.Now(),
			FlowData:  f,
			Stats:     ad.flowStats,
		}
		ad.sendAlert(alert)
	}
}

// checkHighConnectionRate checks for unusually high connection rates
func (ad *AnomalyDetector) checkHighConnectionRate(f *Flow) {
	if ad.flowStats.ConnectionRate > float64(ad.config.AlertThresholds.HighConnectionThreshold) {
		alert := Alert{
			Type:     "HIGH_CONNECTION_RATE",
			Severity: "MEDIUM",
			Message: fmt.Sprintf("High connection rate detected: %.2f connections/s (threshold: %d)",
				ad.flowStats.ConnectionRate, ad.config.AlertThresholds.HighConnectionThreshold),
			Timestamp: time.Now(),
			FlowData:  f,
			Stats:     ad.flowStats,
		}
		ad.sendAlert(alert)
	}
}

// isKnownPort checks if a port is a known/common port
func (ad *AnomalyDetector) isKnownPort(port uint32) bool {
	commonPorts := map[uint32]bool{
		22:    true, // SSH
		23:    true, // Telnet
		25:    true, // SMTP
		53:    true, // DNS
		80:    true, // HTTP
		110:   true, // POP3
		143:   true, // IMAP
		443:   true, // HTTPS
		993:   true, // IMAPS
		995:   true, // POP3S
		3389:  true, // RDP
		5432:  true, // PostgreSQL
		3306:  true, // MySQL
		6379:  true, // Redis
		27017: true, // MongoDB
	}

	if commonPorts[port] {
		return true
	}

	// Check if we've seen this port before and it's not unusual
	ad.knownPorts[port] = true
	return false
}

// isKnownDestination checks if a destination IP is known
func (ad *AnomalyDetector) isKnownDestination(ip string) bool {
	// This is a simplified check - in practice, you'd want more sophisticated logic
	// to determine what constitutes a "known" destination
	if ad.knownDests[ip] {
		return true
	}

	// Add to known destinations after first encounter
	ad.knownDests[ip] = true
	return false
}

// sendAlert sends an alert to the alert channel
func (ad *AnomalyDetector) sendAlert(alert Alert) {
	select {
	case ad.alertChannel <- alert:
		ad.logger.WithFields(logrus.Fields{
			"type":     alert.Type,
			"severity": alert.Severity,
			"message":  alert.Message,
		}).Warn("Anomaly detected")
	default:
		ad.logger.Error("Alert channel is full, dropping alert")
	}
}

// GetAlertChannel returns the alert channel
func (ad *AnomalyDetector) GetAlertChannel() <-chan Alert {
	return ad.alertChannel
}

// ResetStats resets the flow statistics
func (ad *AnomalyDetector) ResetStats() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.flowStats = &FlowStats{LastReset: time.Now()}
	ad.unusualPorts = make(map[uint32]int)
	ad.unusualDests = make(map[string]int)
	ad.unusualNamespace = make(map[string]int)

	// Reset namespace stats
	for _, nsStats := range ad.namespaceStats {
		nsStats.TotalFlows = 0
		nsStats.TotalBytes = 0
		nsStats.TotalConnections = 0
		nsStats.DroppedPackets = 0
		nsStats.LastReset = time.Now()
		nsStats.FlowRate = 0
		nsStats.ByteRate = 0
		nsStats.ConnectionRate = 0
		nsStats.DropRate = 0
	}
}

// updateNamespaceStats updates statistics for specific namespaces
func (ad *AnomalyDetector) updateNamespaceStats(f *Flow, bytes int64) {
	// Update source namespace stats
	if f.Source != nil && f.Source.Namespace != "" {
		ad.updateNamespaceStatsForNamespace(f.Source.Namespace, bytes, f)
	}

	// Update destination namespace stats
	if f.Destination != nil && f.Destination.Namespace != "" {
		ad.updateNamespaceStatsForNamespace(f.Destination.Namespace, bytes, f)
	}
}

// updateNamespaceStatsForNamespace updates stats for a specific namespace
func (ad *AnomalyDetector) updateNamespaceStatsForNamespace(namespace string, bytes int64, f *Flow) {
	nsStats, exists := ad.namespaceStats[namespace]
	if !exists {
		nsStats = &NamespaceStats{
			Namespace: namespace,
			LastReset: time.Now(),
		}
		ad.namespaceStats[namespace] = nsStats
	}

	nsStats.TotalFlows++
	nsStats.TotalBytes += bytes

	if f.Type == FlowType_L3_L4 || f.Type == FlowType_L7 {
		nsStats.TotalConnections++
	}

	if f.Verdict == Verdict_DROPPED {
		nsStats.DroppedPackets++
	}

	// Calculate rates for this namespace
	now := time.Now()
	timeDiff := now.Sub(nsStats.LastReset).Seconds()
	if timeDiff > 0 {
		nsStats.FlowRate = float64(nsStats.TotalFlows) / timeDiff
		nsStats.ByteRate = float64(nsStats.TotalBytes) / timeDiff
		nsStats.ConnectionRate = float64(nsStats.TotalConnections) / timeDiff
		nsStats.DropRate = (float64(nsStats.DroppedPackets) / float64(nsStats.TotalFlows)) * 100
	}
}

// checkNamespaceAnomalies checks for anomalies related to namespaces
func (ad *AnomalyDetector) checkNamespaceAnomalies(f *Flow) {
	// Check for unusual namespace activity
	if f.Source != nil && f.Source.Namespace != "" {
		ad.checkUnusualNamespaceActivity(f.Source.Namespace, f, "source")
	}

	if f.Destination != nil && f.Destination.Namespace != "" {
		ad.checkUnusualNamespaceActivity(f.Destination.Namespace, f, "destination")
	}

	// Check for cross-namespace communication anomalies
	ad.checkCrossNamespaceAnomalies(f)
}

// checkUnusualNamespaceActivity checks for unusual activity in a namespace
func (ad *AnomalyDetector) checkUnusualNamespaceActivity(namespace string, f *Flow, direction string) {
	nsStats, exists := ad.namespaceStats[namespace]
	if !exists {
		return
	}

	// Check for high bandwidth in namespace
	if nsStats.ByteRate > float64(ad.config.AlertThresholds.NamespaceBandwidthThreshold) {
		alert := Alert{
			Type:     "HIGH_NAMESPACE_BANDWIDTH",
			Severity: "MEDIUM",
			Message: fmt.Sprintf("High bandwidth detected in namespace '%s' (%s): %.2f bytes/s",
				namespace, direction, nsStats.ByteRate),
			Timestamp: time.Now(),
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}

	// Check for high connection rate in namespace
	if nsStats.ConnectionRate > float64(ad.config.AlertThresholds.NamespaceConnectionThreshold) {
		alert := Alert{
			Type:     "HIGH_NAMESPACE_CONNECTION_RATE",
			Severity: "MEDIUM",
			Message: fmt.Sprintf("High connection rate detected in namespace '%s' (%s): %.2f connections/s",
				namespace, direction, nsStats.ConnectionRate),
			Timestamp: time.Now(),
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}

	// Check for high drop rate in namespace
	if nsStats.DropRate > ad.config.AlertThresholds.DropRateThreshold {
		alert := Alert{
			Type:     "HIGH_NAMESPACE_DROP_RATE",
			Severity: "HIGH",
			Message: fmt.Sprintf("High drop rate detected in namespace '%s' (%s): %.2f%%",
				namespace, direction, nsStats.DropRate),
			Timestamp: time.Now(),
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}
}

// checkCrossNamespaceAnomalies checks for anomalies in cross-namespace communication
func (ad *AnomalyDetector) checkCrossNamespaceAnomalies(f *Flow) {
	if f.Source == nil || f.Destination == nil {
		return
	}

	sourceNS := f.Source.Namespace
	destNS := f.Destination.Namespace

	// Skip if same namespace or empty namespaces
	if sourceNS == "" || destNS == "" || sourceNS == destNS {
		return
	}

	// Check for unusual cross-namespace communication
	crossNSKey := fmt.Sprintf("%s->%s", sourceNS, destNS)
	ad.unusualNamespace[crossNSKey]++

	// Alert if too many cross-namespace connections
	if ad.unusualNamespace[crossNSKey] > ad.config.AlertThresholds.CrossNamespaceThreshold {
		alert := Alert{
			Type:     "UNUSUAL_CROSS_NAMESPACE",
			Severity: "MEDIUM",
			Message: fmt.Sprintf("Unusual cross-namespace communication detected: %s (%d connections)",
				crossNSKey, ad.unusualNamespace[crossNSKey]),
			Timestamp: time.Now(),
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}
}
