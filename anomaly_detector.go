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

	// Traffic Spike Detection
	trafficBaseline map[string]float64         // pod-pair -> baseline bytes/min
	trafficHistory  map[string][]TrafficSample // pod-pair -> recent samples

	// DDoS Pattern Detection
	connectionCounts map[string]int       // source-dest -> connection count
	connectionWindow map[string]time.Time // source-dest -> window start time

	// High Error Rate Detection
	httpStats map[string]*HTTPStats // endpoint -> HTTP statistics

	// Error Burst Detection
	errorBurstHistory map[string][]ErrorSample // endpoint -> recent error samples
}

// ErrorSample represents an error measurement
type ErrorSample struct {
	Timestamp time.Time
	IsError   bool
}

// TrafficSample represents a traffic measurement
type TrafficSample struct {
	Timestamp time.Time
	Bytes     uint64
}

// HTTPStats holds HTTP request statistics
type HTTPStats struct {
	TotalRequests int64
	ErrorRequests int64
	LastReset     time.Time
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
		config:       config,
		logger:       logger,
		flowStats:    &FlowStats{LastReset: time.Now()},
		alertChannel: make(chan Alert, 100),

		// Initialize new detection maps
		trafficBaseline:   make(map[string]float64),
		trafficHistory:    make(map[string][]TrafficSample),
		connectionCounts:  make(map[string]int),
		connectionWindow:  make(map[string]time.Time),
		httpStats:         make(map[string]*HTTPStats),
		errorBurstHistory: make(map[string][]ErrorSample),
	}
}

// ProcessFlow processes a single flow and checks for anomalies
func (ad *AnomalyDetector) ProcessFlow(ctx context.Context, f *Flow) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Update statistics
	ad.updateStats(f)

	// Check for anomalies based on 4 rules
	ad.checkTrafficSpike(f)
	ad.checkDDoSPattern(f)
	ad.checkHighErrorRate(f)
	ad.checkErrorBurst(f)
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

// checkTrafficSpike checks for traffic spike anomalies (Rule 1)
func (ad *AnomalyDetector) checkTrafficSpike(f *Flow) {
	if f.Source == nil || f.Destination == nil || f.IP == nil {
		return
	}

	// Create pod-pair key
	podPair := fmt.Sprintf("%s-%s", f.Source.PodName, f.Destination.PodName)

	// Calculate bytes for this flow
	bytes := ad.calculateBytes(f)
	if bytes == 0 {
		return
	}

	// Add sample to history
	now := time.Now()
	sample := TrafficSample{
		Timestamp: now,
		Bytes:     uint64(bytes),
	}

	ad.trafficHistory[podPair] = append(ad.trafficHistory[podPair], sample)

	// Keep only last 5 minutes of data
	fiveMinutesAgo := now.Add(-5 * time.Minute)
	var recentSamples []TrafficSample
	for _, s := range ad.trafficHistory[podPair] {
		if s.Timestamp.After(fiveMinutesAgo) {
			recentSamples = append(recentSamples, s)
		}
	}
	ad.trafficHistory[podPair] = recentSamples

	// Calculate baseline (average of last 5 minutes)
	if len(ad.trafficHistory[podPair]) < 2 {
		return
	}

	var totalBytes float64
	for _, s := range ad.trafficHistory[podPair] {
		totalBytes += float64(s.Bytes)
	}
	baseline := totalBytes / float64(len(ad.trafficHistory[podPair]))
	ad.trafficBaseline[podPair] = baseline

	// Check for traffic spike: > 200% of baseline
	if float64(bytes) > 2.0*baseline {
		alert := Alert{
			Type:     "TRAFFIC_SPIKE",
			Severity: "HIGH",
			Message: fmt.Sprintf("Traffic spike detected: Pod %s -> %s: %.2f bytes (baseline: %.2f, increase: %.1f%%)",
				f.Source.PodName, f.Destination.PodName, float64(bytes), baseline, (float64(bytes)/baseline)*100),
			Timestamp: now,
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}
}

// checkDDoSPattern checks for DDoS pattern anomalies (Rule 2)
func (ad *AnomalyDetector) checkDDoSPattern(f *Flow) {
	if f.IP == nil || f.L4 == nil {
		return
	}

	// Create source-destination key
	sourceDest := fmt.Sprintf("%s-%s", f.IP.Source, f.IP.Destination)
	now := time.Now()

	// Check if we need to reset the window (10 seconds)
	if windowStart, exists := ad.connectionWindow[sourceDest]; exists {
		if now.Sub(windowStart) > 10*time.Second {
			// Reset window
			ad.connectionCounts[sourceDest] = 0
			ad.connectionWindow[sourceDest] = now
		}
	} else {
		// Initialize window
		ad.connectionWindow[sourceDest] = now
		ad.connectionCounts[sourceDest] = 0
	}

	// Increment connection count
	ad.connectionCounts[sourceDest]++

	// Check for DDoS pattern: > 100 connections in 10 seconds
	if ad.connectionCounts[sourceDest] > 100 {
		alert := Alert{
			Type:     "DDOS_PATTERN",
			Severity: "HIGH",
			Message: fmt.Sprintf("DDoS pattern detected: %s -> %s: %d connections in 10 seconds",
				f.IP.Source, f.IP.Destination, ad.connectionCounts[sourceDest]),
			Timestamp: now,
			FlowData:  f,
		}
		ad.sendAlert(alert)
	}
}

// checkHighErrorRate checks for high HTTP error rate anomalies (Rule 3)
func (ad *AnomalyDetector) checkHighErrorRate(f *Flow) {
	// Only check HTTP flows
	if f.L7 == nil || f.L7.Type != L7Type_HTTP {
		return
	}

	if f.Destination == nil {
		return
	}

	// Create endpoint key
	endpoint := fmt.Sprintf("%s:%s", f.Destination.PodName, f.Destination.Namespace)
	now := time.Now()

	// Initialize HTTP stats if not exists
	if _, exists := ad.httpStats[endpoint]; !exists {
		ad.httpStats[endpoint] = &HTTPStats{
			LastReset: now,
		}
	}

	stats := ad.httpStats[endpoint]

	// Reset stats every minute
	if now.Sub(stats.LastReset) > time.Minute {
		stats.TotalRequests = 0
		stats.ErrorRequests = 0
		stats.LastReset = now
	}

	// Increment total requests
	stats.TotalRequests++

	// Check if this is an error (simplified - in real implementation you'd parse HTTP response)
	// For now, we'll assume dropped packets or certain verdicts indicate errors
	if f.Verdict == Verdict_DROPPED || f.Verdict == Verdict_ERROR {
		stats.ErrorRequests++
	}

	// Calculate error rate
	if stats.TotalRequests > 0 {
		errorRate := float64(stats.ErrorRequests) / float64(stats.TotalRequests) * 100

		// Check for high error rate: > 5%
		if errorRate > 5.0 {
			alert := Alert{
				Type:     "HIGH_ERROR_RATE",
				Severity: "HIGH",
				Message: fmt.Sprintf("High HTTP error rate detected: %s: %.2f%% (%d/%d requests)",
					endpoint, errorRate, stats.ErrorRequests, stats.TotalRequests),
				Timestamp: now,
				FlowData:  f,
			}
			ad.sendAlert(alert)
		}
	}
}

// checkErrorBurst checks for error burst anomalies (Rule 4)
func (ad *AnomalyDetector) checkErrorBurst(f *Flow) {
	// Only check HTTP flows
	if f.L7 == nil || f.L7.Type != L7Type_HTTP {
		return
	}

	if f.Destination == nil {
		return
	}

	// Create endpoint key
	endpoint := fmt.Sprintf("%s:%s", f.Destination.PodName, f.Destination.Namespace)
	now := time.Now()

	// Check if this is an error
	isError := f.Verdict == Verdict_DROPPED || f.Verdict == Verdict_ERROR

	// Add error sample to history
	sample := ErrorSample{
		Timestamp: now,
		IsError:   isError,
	}

	ad.errorBurstHistory[endpoint] = append(ad.errorBurstHistory[endpoint], sample)

	// Keep only last 30 seconds of data
	thirtySecondsAgo := now.Add(-30 * time.Second)
	var recentSamples []ErrorSample
	for _, s := range ad.errorBurstHistory[endpoint] {
		if s.Timestamp.After(thirtySecondsAgo) {
			recentSamples = append(recentSamples, s)
		}
	}
	ad.errorBurstHistory[endpoint] = recentSamples

	// Check for error burst: > 10 errors in 30 seconds
	if len(ad.errorBurstHistory[endpoint]) >= 10 {
		errorCount := 0
		for _, s := range ad.errorBurstHistory[endpoint] {
			if s.IsError {
				errorCount++
			}
		}

		// Alert if more than 10 errors in 30 seconds
		if errorCount > 10 {
			alert := Alert{
				Type:     "ERROR_BURST",
				Severity: "HIGH",
				Message: fmt.Sprintf("Error burst detected: %s: %d errors in 30 seconds",
					endpoint, errorCount),
				Timestamp: now,
				FlowData:  f,
			}
			ad.sendAlert(alert)
		}
	}
}

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

// ResetStats resets the flow statistics
func (ad *AnomalyDetector) ResetStats() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.flowStats = &FlowStats{LastReset: time.Now()}

	// Reset new detection maps
	ad.trafficBaseline = make(map[string]float64)
	ad.trafficHistory = make(map[string][]TrafficSample)
	ad.connectionCounts = make(map[string]int)
	ad.connectionWindow = make(map[string]time.Time)
	ad.httpStats = make(map[string]*HTTPStats)
	ad.errorBurstHistory = make(map[string][]ErrorSample)
}
