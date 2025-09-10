package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// HubbleSimpleClient handles connection to Hubble server via gRPC
type HubbleSimpleClient struct {
	conn   *grpc.ClientConn
	logger *logrus.Logger
}

// NewHubbleSimpleClient creates a new simple gRPC Hubble client
func NewHubbleSimpleClient(serverAddr string, logger *logrus.Logger) (*HubbleSimpleClient, error) {
	logger.WithField("server", serverAddr).Info("Creating simple gRPC Hubble client")

	// Connect to Hubble server via gRPC
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble server: %v", err)
	}

	return &HubbleSimpleClient{
		conn:   conn,
		logger: logger,
	}, nil
}

// Close closes the Hubble client connection
func (hc *HubbleSimpleClient) Close() error {
	hc.logger.Info("Closing simple gRPC Hubble client")
	return hc.conn.Close()
}

// StartFlowStreaming starts streaming flows from Hubble server via gRPC
func (hc *HubbleSimpleClient) StartFlowStreaming(ctx context.Context, detector *AnomalyDetector, flowFilters []string) error {
	hc.logger.Info("Starting flow streaming from Hubble server via gRPC")

	// For now, we'll use a simple approach by calling hubble CLI
	// In a production environment, you would implement proper gRPC calls
	// to the Hubble Observer service

	hc.logger.Info("Using mock data for now - implement proper gRPC calls to Hubble Observer service")

	// Generate mock flows for demonstration
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	flowCount := 0
	for {
		select {
		case <-ctx.Done():
			hc.logger.Info("Flow streaming stopped due to context cancellation")
			return ctx.Err()
		case <-ticker.C:
			// Generate mock flow with realistic data
			flow := hc.generateRealisticMockFlow(flowCount)
			flowCount++

			// Process flow with anomaly detector
			detector.ProcessFlow(ctx, flow)
		}
	}
}

// GetServerStatus checks if Hubble server is accessible
func (hc *HubbleSimpleClient) GetServerStatus(ctx context.Context) error {
	hc.logger.Info("Checking Hubble server status via gRPC")

	// Test the gRPC connection
	state := hc.conn.GetState()
	if state.String() != "READY" {
		return fmt.Errorf("gRPC connection not ready: %s", state.String())
	}

	hc.logger.Info("gRPC connection is ready")
	return nil
}

// generateRealisticMockFlow generates a realistic mock flow
func (hc *HubbleSimpleClient) generateRealisticMockFlow(count int) *Flow {
	now := time.Now()

	// Simulate different types of flows
	flowTypes := []FlowType{FlowType_L3_L4, FlowType_L7}
	verdicts := []Verdict{Verdict_FORWARDED, Verdict_DROPPED}

	flowType := flowTypes[count%len(flowTypes)]
	verdict := verdicts[count%len(verdicts)]

	// Generate realistic namespaces and pods
	namespaces := []string{"default", "kube-system", "monitoring", "production", "staging", "development"}
	services := []string{"web-service", "api-service", "db-service", "cache-service", "auth-service", "frontend", "backend"}

	sourceNS := namespaces[count%len(namespaces)]
	destNS := namespaces[(count+1)%len(namespaces)]

	// Sometimes generate cross-namespace communication
	if count%3 == 0 {
		for destNS == sourceNS {
			destNS = namespaces[(count+2)%len(namespaces)]
		}
	}

	sourceService := services[count%len(services)]
	destService := services[(count+1)%len(services)]

	// Generate realistic ports
	sourcePort := uint32(30000 + (count % 1000))
	destPort := uint32(80 + (count % 10)) // Common ports

	// Sometimes generate unusual ports for anomaly detection
	if count%20 == 0 {
		destPort = uint32(50000 + (count % 1000))
	}

	// Generate realistic bytes
	bytes := uint32(100 + (count % 1000))
	if count%10 == 0 { // 10% chance for high bandwidth
		bytes = uint32(50000 + (count % 50000))
	}

	// Generate realistic TCP flags
	tcpFlags := &TCPFlags{
		SYN: count%10 == 0,
		ACK: count%3 == 0,
		FIN: count%50 == 0,
		RST: count%100 == 0,
		PSH: count%5 == 0,
		URG: count%200 == 0,
	}

	flow := &Flow{
		Time:    &now,
		Verdict: verdict,
		Type:    flowType,
		IP: &IP{
			Source:      fmt.Sprintf("10.0.0.%d", (count%254)+1),
			Destination: fmt.Sprintf("10.0.0.%d", ((count+1)%254)+1),
		},
		L4: &L4{
			TCP: &TCP{
				SourcePort:      sourcePort,
				DestinationPort: destPort,
				Bytes:           bytes,
				Flags:           tcpFlags,
			},
		},
		Source: &Endpoint{
			Namespace:   sourceNS,
			PodName:     fmt.Sprintf("%s-pod-%d", sourceService, count%100),
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
			PodName:     fmt.Sprintf("%s-pod-%d", destService, (count+1)%100),
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
			Type: l7Types[count%len(l7Types)],
		}
	}

	return flow
}
