package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
)

// HubbleClient handles connection to Hubble server
type HubbleClient struct {
	logger *logrus.Logger
}

// NewHubbleClient creates a new Hubble client
func NewHubbleClient(serverAddr string, logger *logrus.Logger) (*HubbleClient, error) {
	logger.WithField("server", serverAddr).Info("Creating Hubble client")

	// In a real implementation, this would connect to the actual Hubble server
	// For demo purposes, we'll create a mock client
	return &HubbleClient{
		logger: logger,
	}, nil
}

// Close closes the Hubble client connection
func (hc *HubbleClient) Close() error {
	hc.logger.Info("Closing Hubble client")
	return nil
}

// StartFlowStreaming starts streaming flows and sends them to the anomaly detector
func (hc *HubbleClient) StartFlowStreaming(ctx context.Context, detector *AnomalyDetector, flowFilters []string) error {
	hc.logger.Info("Starting flow streaming (mock mode)")

	// Mock flow generation for demo purposes
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	flowCount := 0
	for {
		select {
		case <-ctx.Done():
			hc.logger.Info("Flow streaming stopped due to context cancellation")
			return ctx.Err()
		case <-ticker.C:
			// Generate mock flow
			flow := hc.generateMockFlow(flowCount)
			flowCount++

			// Process flow with anomaly detector
			detector.ProcessFlow(ctx, flow)
		}
	}
}

// GetServerStatus checks if Hubble server is accessible
func (hc *HubbleClient) GetServerStatus(ctx context.Context) error {
	hc.logger.Info("Checking Hubble server status (mock mode)")
	// In a real implementation, this would test the actual connection
	return nil
}

// generateMockFlow generates a mock flow for demo purposes
func (hc *HubbleClient) generateMockFlow(count int) *Flow {
	now := time.Now()

	// Simulate different types of flows
	flowTypes := []FlowType{FlowType_L3_L4, FlowType_L7}
	verdicts := []Verdict{Verdict_FORWARDED, Verdict_DROPPED}

	flowType := flowTypes[count%len(flowTypes)]
	verdict := verdicts[count%len(verdicts)]

	// Generate random IPs
	sourceIP := fmt.Sprintf("192.168.1.%d", rand.Intn(254)+1)
	destIP := fmt.Sprintf("10.0.0.%d", rand.Intn(254)+1)

	// Generate random ports
	sourcePort := uint32(rand.Intn(65535) + 1)
	destPort := uint32(rand.Intn(65535) + 1)

	// Sometimes generate unusual ports for anomaly detection
	if rand.Float32() < 0.1 { // 10% chance
		destPort = uint32(rand.Intn(10000) + 50000) // High port numbers
	}

	// Sometimes generate high bandwidth
	bytes := uint32(rand.Intn(1000) + 100)
	if rand.Float32() < 0.05 { // 5% chance for high bandwidth
		bytes = uint32(rand.Intn(100000) + 50000)
	}

	// Generate namespace information
	namespaces := []string{"default", "kube-system", "monitoring", "production", "staging", "development"}
	sourceNS := namespaces[rand.Intn(len(namespaces))]
	destNS := namespaces[rand.Intn(len(namespaces))]

	// Sometimes generate cross-namespace communication
	if rand.Float32() < 0.3 { // 30% chance for cross-namespace
		for destNS == sourceNS {
			destNS = namespaces[rand.Intn(len(namespaces))]
		}
	}

	// Generate pod names
	sourcePod := fmt.Sprintf("pod-%d", rand.Intn(100))
	destPod := fmt.Sprintf("pod-%d", rand.Intn(100))

	// Generate service names
	services := []string{"web-service", "api-service", "db-service", "cache-service", "auth-service"}
	sourceService := services[rand.Intn(len(services))]
	destService := services[rand.Intn(len(services))]

	flow := &Flow{
		Time:    &now,
		Verdict: verdict,
		Type:    flowType,
		IP: &IP{
			Source:      sourceIP,
			Destination: destIP,
		},
		L4: &L4{
			TCP: &TCP{
				SourcePort:      sourcePort,
				DestinationPort: destPort,
				Bytes:           bytes,
				Flags: &TCPFlags{
					SYN: rand.Float32() < 0.3,
					ACK: rand.Float32() < 0.7,
					FIN: rand.Float32() < 0.1,
					RST: rand.Float32() < 0.05,
				},
			},
		},
		Source: &Endpoint{
			Namespace:   sourceNS,
			PodName:     sourcePod,
			ServiceName: sourceService,
			Workload:    fmt.Sprintf("deployment-%s", sourceService),
			Labels: map[string]string{
				"app":         sourceService,
				"version":     "v1.0.0",
				"tier":        "frontend",
				"environment": "production",
			},
		},
		Destination: &Endpoint{
			Namespace:   destNS,
			PodName:     destPod,
			ServiceName: destService,
			Workload:    fmt.Sprintf("deployment-%s", destService),
			Labels: map[string]string{
				"app":         destService,
				"version":     "v1.0.0",
				"tier":        "backend",
				"environment": "production",
			},
		},
	}

	// Sometimes add L7 information
	if flowType == FlowType_L7 {
		l7Types := []L7Type{L7Type_HTTP, L7Type_DNS, L7Type_KAFKA}
		flow.L7 = &L7{
			Type: l7Types[rand.Intn(len(l7Types))],
		}
	}

	return flow
}
