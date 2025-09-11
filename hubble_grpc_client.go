package main

import (
	"context"
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

// GetNamespaces retrieves all available namespaces from Hubble
func (c *HubbleGRPCClient) GetNamespaces(ctx context.Context) ([]string, error) {
	// Create Hubble observer client
	client := observer.NewObserverClient(c.conn)

	// Create request to get namespaces
	req := &observer.GetNamespacesRequest{}

	// Get namespaces
	response, err := client.GetNamespaces(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespaces: %v", err)
	}

	// Extract namespace names
	var namespaces []string
	for _, ns := range response.GetNamespaces() {
		if ns.GetNamespace() != "" {
			namespaces = append(namespaces, ns.GetNamespace())
		}
	}

	return namespaces, nil
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
				SourcePod:      []string{namespace + "/*"},
				DestinationPod: []string{namespace + "/*"},
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
			c.printFlow(flowCount, response)
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
