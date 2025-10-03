package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// HubbleGRPCClient connects to Hubble relay via gRPC
type HubbleGRPCClient struct {
	conn   *grpc.ClientConn
	server string
}

// NewHubbleGRPCClient creates a new gRPC client
func NewHubbleGRPCClient(server string) (*HubbleGRPCClient, error) {
	// Connect to Hubble server via gRPC
	conn, err := grpc.Dial(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble server: %v", err)
	}

	return &HubbleGRPCClient{
		conn:   conn,
		server: server,
	}, nil
}

// Close closes the connection
func (c *HubbleGRPCClient) Close() error {
	return c.conn.Close()
}

// TestConnection tests the connection to Hubble server
func (c *HubbleGRPCClient) TestConnection(ctx context.Context) error {
	// Simple connection test
	state := c.conn.GetState()
	if state.String() == "READY" {
		fmt.Printf("✅ Successfully connected to Hubble relay at %s\n", c.server)
		return nil
	}

	// Wait for connection to be ready
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ready := c.conn.WaitForStateChange(ctx, state)
	if ready {
		fmt.Printf("✅ Successfully connected to Hubble relay at %s\n", c.server)
		return nil
	}

	return fmt.Errorf("connection test failed: connection not ready")
}

// StreamFlows streams flows from Hubble and prints them
func (c *HubbleGRPCClient) StreamFlows(ctx context.Context, namespace string) error {
	fmt.Println("🚀 Starting to stream flows from Hubble relay...")
	if namespace != "" {
		fmt.Printf("📋 Filtering flows for namespace: %s\n", namespace)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 80))

	// Create Hubble observer client
	client := observer.NewObserverClient(c.conn)

	// Create flow request for streaming
	req := &observer.GetFlowsRequest{
		Follow: true, // Stream flows continuously
	}

	// Add namespace filter if specified
	if namespace != "" {
		req.Whitelist = []*observer.FlowFilter{
			{
				SourceLabel: []string{"k8s:io.kubernetes.pod.namespace=" + namespace},
			},
			{
				DestinationLabel: []string{"k8s:io.kubernetes.pod.namespace=" + namespace},
			},
		}
	}

	// Start streaming flows
	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start flow streaming: %v", err)
	}

	flowCount := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nStopped streaming flows")
			return nil
		default:
			// Receive flow from stream
			response, err := stream.Recv()
			if err == io.EOF {
				fmt.Println("Stream ended")
				return nil
			}
			if err != nil {
				return fmt.Errorf("failed to receive flow: %v", err)
			}

			flowCount++
			c.printFlow(flowCount, response)

			// Print raw flow data for debugging
			if flowData, err := json.MarshalIndent(response, "", "  "); err == nil {
				fmt.Printf("RAW FLOW #%d:\n%s\n", flowCount, string(flowData))
			} else {
				fmt.Printf("RAW FLOW #%d: %+v\n", flowCount, response)
			}
		}
	}
}

// printFlow prints a real flow from Hubble gRPC response
func (c *HubbleGRPCClient) printFlow(flowCount int, response *observer.GetFlowsResponse) {
	flow := response.GetFlow()
	if flow == nil {
		return
	}

	// Extract basic flow information
	timeStr := flow.GetTime().AsTime().Format("2006-01-02 15:04:05")
	verdict := flow.GetVerdict().String()

	// Extract IP information
	sourceIP := "unknown"
	destIP := "unknown"
	if flow.GetIP() != nil {
		sourceIP = flow.GetIP().GetSource()
		destIP = flow.GetIP().GetDestination()
	}

	// Extract port information
	sourcePort := "unknown"
	destPort := "unknown"
	if flow.GetL4() != nil {
		if tcp := flow.GetL4().GetTCP(); tcp != nil {
			sourcePort = fmt.Sprintf("%d", tcp.GetSourcePort())
			destPort = fmt.Sprintf("%d", tcp.GetDestinationPort())
		} else if udp := flow.GetL4().GetUDP(); udp != nil {
			sourcePort = fmt.Sprintf("%d", udp.GetSourcePort())
			destPort = fmt.Sprintf("%d", udp.GetDestinationPort())
		}
	}

	// Extract source endpoint information
	sourceInfo := fmt.Sprintf("%s:%s", sourceIP, sourcePort)
	if source := flow.GetSource(); source != nil {
		if source.GetNamespace() != "" {
			sourceInfo += fmt.Sprintf(" (%s/%s)", source.GetNamespace(), source.GetPodName())
		}
		if source.GetID() != 0 {
			sourceInfo += fmt.Sprintf(" [ID:%d]", source.GetID())
		}
	}

	// Extract destination endpoint information
	destInfo := fmt.Sprintf("%s:%s", destIP, destPort)
	if destination := flow.GetDestination(); destination != nil {
		if destination.GetNamespace() != "" {
			destInfo += fmt.Sprintf(" (%s/%s)", destination.GetNamespace(), destination.GetPodName())
		}
		if destination.GetID() != 0 {
			destInfo += fmt.Sprintf(" [ID:%d]", destination.GetID())
		}
	}

	// Extract TCP flags
	tcpFlags := ""
	if flow.GetL4() != nil {
		if tcp := flow.GetL4().GetTCP(); tcp != nil && tcp.GetFlags() != nil {
			flags := []string{}
			if tcp.GetFlags().GetSYN() {
				flags = append(flags, "SYN")
			}
			if tcp.GetFlags().GetACK() {
				flags = append(flags, "ACK")
			}
			if tcp.GetFlags().GetFIN() {
				flags = append(flags, "FIN")
			}
			if tcp.GetFlags().GetRST() {
				flags = append(flags, "RST")
			}
			if tcp.GetFlags().GetPSH() {
				flags = append(flags, "PSH")
			}
			if tcp.GetFlags().GetURG() {
				flags = append(flags, "URG")
			}
			if len(flags) > 0 {
				tcpFlags = strings.Join(flags, ", ")
			}
		}
	}

	// Print flow information
	fmt.Printf("Flow #%d: %s\n", flowCount, timeStr)
	fmt.Printf("  Source: %s\n", sourceInfo)
	fmt.Printf("  Destination: %s\n", destInfo)
	fmt.Printf("  Verdict: %s\n", verdict)
	if tcpFlags != "" {
		fmt.Printf("  TCP Flags: %s\n", tcpFlags)
	}

	fmt.Println("  " + strings.Repeat("-", 50))
}

// StreamFlowsWithDetection streams flows and processes them with anomaly detection
func (c *HubbleGRPCClient) StreamFlowsWithDetection(ctx context.Context, namespace string, detector *AnomalyDetector) error {
	// Create Hubble observer client
	client := observer.NewObserverClient(c.conn)

	// Create request to get flows
	req := &observer.GetFlowsRequest{
		Follow: true, // Stream flows continuously
	}

	// Add namespace filter if specified
	if namespace != "" {
		req.Whitelist = []*observer.FlowFilter{
			{
				SourceLabel: []string{"k8s:io.kubernetes.pod.namespace=" + namespace},
			},
			{
				DestinationLabel: []string{"k8s:io.kubernetes.pod.namespace=" + namespace},
			},
		}
	}

	// Start streaming flows
	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start flow streaming: %v", err)
	}

	flowCount := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n🛑 Stopped streaming flows")
			return nil
		default:
			// Receive flow from stream
			response, err := stream.Recv()
			if err == io.EOF {
				fmt.Println("🛑 Stream ended")
				return nil
			}
			if err != nil {
				return fmt.Errorf("failed to receive flow: %v", err)
			}

			flowCount++

			// Convert Hubble flow to our Flow struct
			flow := c.convertHubbleFlow(response.GetFlow())
			if flow != nil {
				// Process flow with anomaly detection
				detector.ProcessFlow(ctx, flow)
			}
		}
	}
}

// convertHubbleFlow converts Hubble flow to our Flow struct
func (c *HubbleGRPCClient) convertHubbleFlow(hubbleFlow *observer.Flow) *Flow {
	if hubbleFlow == nil {
		return nil
	}

	flow := &Flow{}

	// Convert time
	if hubbleFlow.Time != nil {
		t := hubbleFlow.Time.AsTime()
		flow.Time = &t
	}

	// Convert verdict
	switch hubbleFlow.Verdict {
	case observer.Verdict_FORWARDED:
		flow.Verdict = Verdict_FORWARDED
	case observer.Verdict_DROPPED:
		flow.Verdict = Verdict_DROPPED
	case observer.Verdict_ERROR:
		flow.Verdict = Verdict_ERROR
	default:
		flow.Verdict = Verdict_VERDICT_UNKNOWN
	}

	// Convert IP information
	if hubbleFlow.GetIP() != nil {
		flow.IP = &IP{
			Source:      hubbleFlow.GetIP().GetSource(),
			Destination: hubbleFlow.GetIP().GetDestination(),
		}
	}

	// Convert L4 information
	if hubbleFlow.GetL4() != nil {
		flow.L4 = &L4{}

		if tcp := hubbleFlow.GetL4().GetTCP(); tcp != nil {
			flow.L4.TCP = &TCP{
				SourcePort:      tcp.GetSourcePort(),
				DestinationPort: tcp.GetDestinationPort(),
				Bytes:           0, // Bytes not available in TCP struct
			}

			if flags := tcp.GetFlags(); flags != nil {
				flow.L4.TCP.Flags = &TCPFlags{
					SYN: flags.GetSYN(),
					ACK: flags.GetACK(),
					FIN: flags.GetFIN(),
					RST: flags.GetRST(),
					PSH: flags.GetPSH(),
					URG: flags.GetURG(),
				}
			}
		}

		if udp := hubbleFlow.GetL4().GetUDP(); udp != nil {
			flow.L4.UDP = &UDP{
				SourcePort:      udp.GetSourcePort(),
				DestinationPort: udp.GetDestinationPort(),
				Bytes:           0, // Bytes not available in UDP struct
			}
		}
	}

	// Convert L7 information
	if hubbleFlow.GetL7() != nil {
		flow.L7 = &L7{}

		// Map L7 type to our constants
		l7Type := hubbleFlow.GetL7().GetType()
		switch l7Type {
		case 1: // HTTP
			flow.L7.Type = L7Type_HTTP
		case 2: // KAFKA
			flow.L7.Type = L7Type_KAFKA
		case 3: // DNS
			flow.L7.Type = L7Type_DNS
		default:
			flow.L7.Type = L7Type_UNKNOWN_L7
		}
	}

	// Convert flow type
	switch hubbleFlow.GetType() {
	case observer.FlowType_L3_L4:
		flow.Type = FlowType_L3_L4
	case observer.FlowType_L7:
		flow.Type = FlowType_L7
	default:
		flow.Type = FlowType_UNKNOWN_TYPE
	}

	// Convert source endpoint
	if source := hubbleFlow.GetSource(); source != nil {
		// Convert labels from []string to map[string]string
		labels := make(map[string]string)
		if sourceLabels := source.GetLabels(); sourceLabels != nil {
			for _, label := range sourceLabels {
				parts := strings.SplitN(label, "=", 2)
				if len(parts) == 2 {
					labels[parts[0]] = parts[1]
				}
			}
		}

		flow.Source = &Endpoint{
			Namespace:   source.GetNamespace(),
			PodName:     source.GetPodName(),
			ServiceName: "", // ServiceName not available in Hubble flow
			Workload:    "", // Workload not available in Hubble flow
			Labels:      labels,
		}
	}

	// Convert destination endpoint
	if dest := hubbleFlow.GetDestination(); dest != nil {
		// Convert labels from []string to map[string]string
		labels := make(map[string]string)
		if destLabels := dest.GetLabels(); destLabels != nil {
			for _, label := range destLabels {
				parts := strings.SplitN(label, "=", 2)
				if len(parts) == 2 {
					labels[parts[0]] = parts[1]
				}
			}
		}

		flow.Destination = &Endpoint{
			Namespace:   dest.GetNamespace(),
			PodName:     dest.GetPodName(),
			ServiceName: "", // ServiceName not available in Hubble flow
			Workload:    "", // Workload not available in Hubble flow
			Labels:      labels,
		}
	}

	return flow
}
