package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// AlertHandler handles alert processing and output
type AlertHandler struct {
	logger     *logrus.Logger
	alertFile  *os.File
	alertCount int
}

// NewAlertHandler creates a new alert handler
func NewAlertHandler(logger *logrus.Logger, alertLogFile string) (*AlertHandler, error) {
	var alertFile *os.File
	var err error

	if alertLogFile != "" {
		alertFile, err = os.OpenFile(alertLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open alert log file: %v", err)
		}
	}

	return &AlertHandler{
		logger:    logger,
		alertFile: alertFile,
	}, nil
}

// Close closes the alert handler
func (ah *AlertHandler) Close() error {
	if ah.alertFile != nil {
		return ah.alertFile.Close()
	}
	return nil
}

// HandleAlert processes and outputs an alert
func (ah *AlertHandler) HandleAlert(alert Alert) {
	ah.alertCount++

	// Create alert summary
	summary := fmt.Sprintf("[%s] %s: %s",
		alert.Severity,
		alert.Type,
		alert.Message)

	// Log to console with color coding
	ah.logToConsole(alert, summary)

	// Log to file if configured
	if ah.alertFile != nil {
		ah.logToFile(alert)
	}

	// Log structured data
	ah.logger.WithFields(logrus.Fields{
		"alert_count": ah.alertCount,
		"type":        alert.Type,
		"severity":    alert.Severity,
		"timestamp":   alert.Timestamp,
		"message":     alert.Message,
	}).Warn("Anomaly Alert")
}

// logToConsole logs alert to console with color coding
func (ah *AlertHandler) logToConsole(alert Alert, summary string) {
	timestamp := alert.Timestamp.Format("2006-01-02 15:04:05")

	// Color coding based on severity
	var colorCode string
	switch alert.Severity {
	case "HIGH":
		colorCode = "\033[31m" // Red
	case "MEDIUM":
		colorCode = "\033[33m" // Yellow
	case "LOW":
		colorCode = "\033[34m" // Blue
	default:
		colorCode = "\033[37m" // White
	}

	resetCode := "\033[0m"

	fmt.Printf("%s[%s] %s%s\n", colorCode, timestamp, summary, resetCode)

	// Print additional details if available
	if alert.FlowData != nil {
		ah.printFlowDetails(alert.FlowData)
	}

	if alert.Stats != nil {
		ah.printStatsDetails(alert.Stats)
	}

	fmt.Println("---")
}

// printFlowDetails prints details about the flow that triggered the alert
func (ah *AlertHandler) printFlowDetails(flow *Flow) {
	fmt.Printf("  Flow Details:\n")

	if flow.Time != nil {
		fmt.Printf("    Time: %s\n", flow.Time.Format(time.RFC3339))
	}

	if flow.Verdict != Verdict_VERDICT_UNKNOWN {
		fmt.Printf("    Verdict: %s\n", flow.Verdict.String())
	}

	if flow.IP != nil {
		fmt.Printf("    Source IP: %s\n", flow.IP.Source)
		fmt.Printf("    Destination IP: %s\n", flow.IP.Destination)
	}

	if flow.Source != nil {
		fmt.Printf("    Source Namespace: %s\n", flow.Source.Namespace)
		fmt.Printf("    Source Pod: %s\n", flow.Source.PodName)
		fmt.Printf("    Source Service: %s\n", flow.Source.ServiceName)
		fmt.Printf("    Source Workload: %s\n", flow.Source.Workload)
	}

	if flow.Destination != nil {
		fmt.Printf("    Destination Namespace: %s\n", flow.Destination.Namespace)
		fmt.Printf("    Destination Pod: %s\n", flow.Destination.PodName)
		fmt.Printf("    Destination Service: %s\n", flow.Destination.ServiceName)
		fmt.Printf("    Destination Workload: %s\n", flow.Destination.Workload)
	}

	if flow.L4 != nil {
		if flow.L4.TCP != nil {
			fmt.Printf("    Protocol: TCP\n")
			fmt.Printf("    Source Port: %d\n", flow.L4.TCP.SourcePort)
			fmt.Printf("    Destination Port: %d\n", flow.L4.TCP.DestinationPort)
			if flow.L4.TCP.Flags != nil {
				fmt.Printf("    Flags: %s\n", flow.L4.TCP.Flags.String())
			}
		} else if flow.L4.UDP != nil {
			fmt.Printf("    Protocol: UDP\n")
			fmt.Printf("    Source Port: %d\n", flow.L4.UDP.SourcePort)
			fmt.Printf("    Destination Port: %d\n", flow.L4.UDP.DestinationPort)
		}
	}

	if flow.L7 != nil {
		fmt.Printf("    L7 Protocol: %s\n", flow.L7.Type.String())
	}
}

// printStatsDetails prints current flow statistics
func (ah *AlertHandler) printStatsDetails(stats *FlowStats) {
	fmt.Printf("  Current Statistics:\n")
	fmt.Printf("    Total Flows: %d\n", stats.TotalFlows)
	fmt.Printf("    Total Bytes: %d\n", stats.TotalBytes)
	fmt.Printf("    Total Connections: %d\n", stats.TotalConnections)
	fmt.Printf("    Flow Rate: %.2f flows/s\n", stats.FlowRate)
	fmt.Printf("    Byte Rate: %.2f bytes/s\n", stats.ByteRate)
	fmt.Printf("    Connection Rate: %.2f connections/s\n", stats.ConnectionRate)
	fmt.Printf("    Drop Rate: %.2f%%\n", stats.DropRate)
}

// logToFile logs alert to file in JSON format
func (ah *AlertHandler) logToFile(alert Alert) {
	alertJSON, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		ah.logger.WithError(err).Error("Failed to marshal alert to JSON")
		return
	}

	_, err = ah.alertFile.WriteString(string(alertJSON) + "\n")
	if err != nil {
		ah.logger.WithError(err).Error("Failed to write alert to file")
	}
}

// GetAlertCount returns the total number of alerts handled
func (ah *AlertHandler) GetAlertCount() int {
	return ah.alertCount
}

// PrintSummary prints a summary of alerts
func (ah *AlertHandler) PrintSummary() {
	fmt.Printf("\n=== Alert Summary ===\n")
	fmt.Printf("Total Alerts: %d\n", ah.alertCount)
	fmt.Printf("Alert Log File: %s\n", ah.alertFile.Name())
	fmt.Printf("===================\n")
}
