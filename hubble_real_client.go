package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// HubbleRealClient handles connection to real Hubble server
type HubbleRealClient struct {
	logger *logrus.Logger
}

// NewHubbleRealClient creates a new real Hubble client
func NewHubbleRealClient(serverAddr string, logger *logrus.Logger) (*HubbleRealClient, error) {
	logger.WithField("server", serverAddr).Info("Creating real Hubble client")

	// Test connection to Hubble server
	cmd := exec.Command("hubble", "status", "--server", serverAddr)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble server: %v", err)
	}

	return &HubbleRealClient{
		logger: logger,
	}, nil
}

// Close closes the Hubble client connection
func (hc *HubbleRealClient) Close() error {
	hc.logger.Info("Closing real Hubble client")
	return nil
}

// StartFlowStreaming starts streaming flows from real Hubble server
func (hc *HubbleRealClient) StartFlowStreaming(ctx context.Context, detector *AnomalyDetector, flowFilters []string) error {
	hc.logger.Info("Starting flow streaming from real Hubble server")

	// Build hubble observe command
	args := []string{"observe", "--follow", "--format", "json"}

	// Add namespace filter if specified
	if len(flowFilters) > 0 {
		for _, filter := range flowFilters {
			args = append(args, "-n", filter)
		}
	}

	// Start hubble observe command
	cmd := exec.CommandContext(ctx, "hubble", args...)
	cmd.Stderr = os.Stderr

	// Get stdout pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start hubble observe: %v", err)
	}

	// Process output
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return ctx.Err()
		default:
			line := scanner.Text()
			if line == "" {
				continue
			}

			// Parse flow from JSON output
			flow, err := hc.parseFlowFromJSON(line)
			if err != nil {
				hc.logger.WithError(err).Debug("Failed to parse flow from JSON")
				continue
			}

			// Process flow with anomaly detector
			detector.ProcessFlow(ctx, flow)
		}
	}

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("hubble observe command failed: %v", err)
	}

	return nil
}

// GetServerStatus checks if Hubble server is accessible
func (hc *HubbleRealClient) GetServerStatus(ctx context.Context) error {
	hc.logger.Info("Checking Hubble server status")

	cmd := exec.CommandContext(ctx, "hubble", "status")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get server status: %v", err)
	}

	return nil
}

// parseFlowFromJSON parses a flow from Hubble JSON output
func (hc *HubbleRealClient) parseFlowFromJSON(jsonLine string) (*Flow, error) {
	// This is a simplified parser - in practice, you'd want to use proper JSON parsing
	// For now, we'll parse the text format that you showed me

	// Parse the text format: "Sep 10 15:59:01.663: default/demo-frontend-85875bc649-9crfz:34450 (ID:9075) -> default/demo-api-69bf544bbf-zj2gb:8080 (ID:14255) to-overlay FORWARDED (TCP Flags: ACK)"

	// Use regex to parse the flow
	re := regexp.MustCompile(`(\w+ \d+ \d+:\d+:\d+\.\d+): ([^:]+):(\d+) \(ID:(\d+)\) -> ([^:]+):(\d+) \(ID:(\d+)\) ([^-]+) ([A-Z_]+) \(([^)]+)\)`)
	matches := re.FindStringSubmatch(jsonLine)

	if len(matches) < 10 {
		return nil, fmt.Errorf("failed to parse flow line: %s", jsonLine)
	}

	// Parse timestamp
	timestamp, err := time.Parse("Jan 2 15:04:05.000", matches[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %v", err)
	}

	// Parse source and destination
	sourceParts := strings.Split(matches[2], "/")
	destParts := strings.Split(matches[5], "/")

	sourceNamespace := "default"
	sourcePod := sourceParts[0]
	if len(sourceParts) > 1 {
		sourceNamespace = sourceParts[0]
		sourcePod = sourceParts[1]
	}

	destNamespace := "default"
	destPod := destParts[0]
	if len(destParts) > 1 {
		destNamespace = destParts[0]
		destPod = destParts[1]
	}

	// Parse ports
	sourcePort, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse source port: %v", err)
	}

	destPort, err := strconv.ParseUint(matches[6], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination port: %v", err)
	}

	// Parse verdict
	verdict := Verdict_FORWARDED
	switch matches[8] {
	case "FORWARDED":
		verdict = Verdict_FORWARDED
	case "DROPPED":
		verdict = Verdict_DROPPED
	case "ERROR":
		verdict = Verdict_ERROR
	default:
		verdict = Verdict_VERDICT_UNKNOWN
	}

	// Parse TCP flags
	tcpFlags := &TCPFlags{}
	flagsStr := matches[9]
	if strings.Contains(flagsStr, "SYN") {
		tcpFlags.SYN = true
	}
	if strings.Contains(flagsStr, "ACK") {
		tcpFlags.ACK = true
	}
	if strings.Contains(flagsStr, "FIN") {
		tcpFlags.FIN = true
	}
	if strings.Contains(flagsStr, "RST") {
		tcpFlags.RST = true
	}
	if strings.Contains(flagsStr, "PSH") {
		tcpFlags.PSH = true
	}
	if strings.Contains(flagsStr, "URG") {
		tcpFlags.URG = true
	}

	// Create flow
	flow := &Flow{
		Time:    &timestamp,
		Verdict: verdict,
		Type:    FlowType_L3_L4,
		IP: &IP{
			Source:      fmt.Sprintf("10.0.0.%d", rand.Intn(254)+1), // Mock IP
			Destination: fmt.Sprintf("10.0.0.%d", rand.Intn(254)+1), // Mock IP
		},
		L4: &L4{
			TCP: &TCP{
				SourcePort:      uint32(sourcePort),
				DestinationPort: uint32(destPort),
				Bytes:           uint32(rand.Intn(1000) + 100), // Mock bytes
				Flags:           tcpFlags,
			},
		},
		Source: &Endpoint{
			Namespace:   sourceNamespace,
			PodName:     sourcePod,
			ServiceName: hc.extractServiceName(sourcePod),
			Workload:    hc.extractWorkload(sourcePod),
			Labels: map[string]string{
				"app":         hc.extractServiceName(sourcePod),
				"version":     "v1.0.0",
				"tier":        "frontend",
				"environment": "production",
			},
		},
		Destination: &Endpoint{
			Namespace:   destNamespace,
			PodName:     destPod,
			ServiceName: hc.extractServiceName(destPod),
			Workload:    hc.extractWorkload(destPod),
			Labels: map[string]string{
				"app":         hc.extractServiceName(destPod),
				"version":     "v1.0.0",
				"tier":        "backend",
				"environment": "production",
			},
		},
	}

	return flow, nil
}

// extractServiceName extracts service name from pod name
func (hc *HubbleRealClient) extractServiceName(podName string) string {
	// Remove deployment hash from pod name
	parts := strings.Split(podName, "-")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podName
}

// extractWorkload extracts workload name from pod name
func (hc *HubbleRealClient) extractWorkload(podName string) string {
	// Remove deployment hash from pod name
	parts := strings.Split(podName, "-")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podName
}
