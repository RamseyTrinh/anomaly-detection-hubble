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

// TestConnection tests the connection to Hubble server
func (c *HubbleGRPCClient) TestConnection(ctx context.Context) error {
	// Simple connection test
	state := c.conn.GetState()
	if state.String() == "READY" {
		fmt.Printf("Successfully connected to Hubble relay at %s\n", c.server)
		return nil
	}

	// Wait for connection to be ready
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ready := c.conn.WaitForStateChange(ctx, state)
	if ready {
		fmt.Printf("Successfully connected to Hubble relay at %s\n", c.server)
		return nil
	}

	return fmt.Errorf("connection test failed: connection not ready")
}

// StreamFlows streams flows from Hubble and saves them to Redis
func (c *HubbleGRPCClient) StreamFlows(ctx context.Context, namespace string, flowCache *FlowCache) error {
	fmt.Println("🚀 Starting to stream flows from Hubble relay...")
	if namespace != "" {
		fmt.Printf("📋 Filtering flows for namespace: %s\n", namespace)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 80))

	client := observer.NewObserverClient(c.conn)

	req := &observer.GetFlowsRequest{
		Follow: true, // Stream flows continuously
	}

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

	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start flow streaming: %v", err)
	}

	flowCount := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n Stopped streaming flows")
			return nil
		default:
			// Receive flow from stream
			response, err := stream.Recv()
			if err == io.EOF {
				fmt.Println(" Stream ended")
				return nil
			}
			if err != nil {
				return fmt.Errorf("failed to receive flow: %v", err)
			}

			flowCount++

			// Convert Hubble flow to our Flow struct and save to Redis
			flow := c.convertHubbleFlow(response.GetFlow())
			if flow != nil && flowCache != nil {
				flowCache.AddFlow(flow)
				fmt.Printf("Saved flow #%d to Redis\n", flowCount)
			}

			// Also print flow details for viewing
			c.printFlow(flowCount, response)
		}
	}
}

// StreamFlowsViewOnly streams flows from Hubble and only prints them (no Redis)
func (c *HubbleGRPCClient) StreamFlowsViewOnly(ctx context.Context, namespace string) error {
	return c.StreamFlows(ctx, namespace, nil)
}

func (c *HubbleGRPCClient) printFlow(flowCount int, response *observer.GetFlowsResponse) {
	flow := response.GetFlow()
	if flow == nil {
		return
	}

	timeStr := flow.GetTime().AsTime().Format("2006-01-02 15:04:05")
	verdict := flow.GetVerdict().String()

	sourceIP := "unknown"
	destIP := "unknown"
	if flow.GetIP() != nil {
		sourceIP = flow.GetIP().GetSource()
		destIP = flow.GetIP().GetDestination()
	}

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

	sourceInfo := fmt.Sprintf("%s:%s", sourceIP, sourcePort)
	if source := flow.GetSource(); source != nil {
		if source.GetNamespace() != "" {
			sourceInfo += fmt.Sprintf(" (%s/%s)", source.GetNamespace(), source.GetPodName())
		}
		if source.GetID() != 0 {
			sourceInfo += fmt.Sprintf(" [ID:%d]", source.GetID())
		}
	}

	destInfo := fmt.Sprintf("%s:%s", destIP, destPort)
	if destination := flow.GetDestination(); destination != nil {
		if destination.GetNamespace() != "" {
			destInfo += fmt.Sprintf(" (%s/%s)", destination.GetNamespace(), destination.GetPodName())
		}
		if destination.GetID() != 0 {
			destInfo += fmt.Sprintf(" [ID:%d]", destination.GetID())
		}
	}

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

	fmt.Printf("Flow #%d: %s\n", flowCount, timeStr)
	fmt.Printf("  Source: %s\n", sourceInfo)
	fmt.Printf("  Destination: %s\n", destInfo)
	fmt.Printf("  Verdict: %s\n", verdict)
	if tcpFlags != "" {
		fmt.Printf("  TCP Flags: %s\n", tcpFlags)
	}

	fmt.Println("  " + strings.Repeat("-", 50))
}

func (c *HubbleGRPCClient) StreamFlowsWithDetection(ctx context.Context, namespace string, detector *AnomalyDetector) error {
	// Create Hubble observer client
	client := observer.NewObserverClient(c.conn)

	req := &observer.GetFlowsRequest{
		Follow: true, // Stream flows continuously
	}

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
			response, err := stream.Recv()
			if err == io.EOF {
				fmt.Println("Stream ended")
				return nil
			}
			if err != nil {
				return fmt.Errorf("failed to receive flow: %v", err)
			}

			flowCount++

			flow := c.convertHubbleFlow(response.GetFlow())
			if flow != nil {
				detector.ProcessFlow(ctx, flow)
			}
		}
	}
}

func (c *HubbleGRPCClient) convertHubbleFlow(hubbleFlow *observer.Flow) *Flow {
	if hubbleFlow == nil {
		return nil
	}

	flow := &Flow{}

	if hubbleFlow.Time != nil {
		t := hubbleFlow.Time.AsTime()
		flow.Time = &t
	}

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

	if hubbleFlow.GetIP() != nil {
		flow.IP = &IP{
			Source:      hubbleFlow.GetIP().GetSource(),
			Destination: hubbleFlow.GetIP().GetDestination(),
		}
	}

	if hubbleFlow.GetL4() != nil {
		flow.L4 = &L4{}

		if tcp := hubbleFlow.GetL4().GetTCP(); tcp != nil {
			flow.L4.TCP = &TCP{
				SourcePort:      tcp.GetSourcePort(),
				DestinationPort: tcp.GetDestinationPort(),
				Bytes:           0,
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
				Bytes:           0,
			}
		}
	}

	// Convert L7 information
	if hubbleFlow.GetL7() != nil {
		flow.L7 = &L7{}

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

	switch hubbleFlow.GetType() {
	case observer.FlowType_L3_L4:
		flow.Type = FlowType_L3_L4
	case observer.FlowType_L7:
		flow.Type = FlowType_L7
	default:
		flow.Type = FlowType_UNKNOWN_TYPE
	}

	if source := hubbleFlow.GetSource(); source != nil {
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
			ServiceName: "",
			Workload:    "",
			Labels:      labels,
		}
	}

	// Convert destination endpoint
	if dest := hubbleFlow.GetDestination(); dest != nil {
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
