package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/sirupsen/logrus"
)

// GetObserverClient returns the observer client for direct gRPC calls
func (c *HubbleGRPCClient) GetObserverClient() observer.ObserverClient {
	return observer.NewObserverClient(c.conn)
}

// convertGRPCFlowToFlow converts a gRPC flow to our Flow struct
func convertGRPCFlowToFlow(grpcFlow *observer.Flow) *Flow {
	if grpcFlow == nil {
		return nil
	}

	flow := &Flow{}

	// Set time
	if grpcFlow.GetTime() != nil {
		time := grpcFlow.GetTime().AsTime()
		flow.Time = &time
	}

	// Set verdict
	switch grpcFlow.GetVerdict() {
	case observer.Verdict_FORWARDED:
		flow.Verdict = Verdict_FORWARDED
	case observer.Verdict_DROPPED:
		flow.Verdict = Verdict_DROPPED
	case observer.Verdict_ERROR:
		flow.Verdict = Verdict_ERROR
	default:
		flow.Verdict = Verdict_FORWARDED
	}

	// Set flow type
	switch grpcFlow.GetType() {
	case observer.FlowType_L3_L4:
		flow.Type = FlowType_L3_L4
	case observer.FlowType_L7:
		flow.Type = FlowType_L7
	default:
		flow.Type = FlowType_L3_L4
	}

	// Set IP information
	if grpcFlow.GetIP() != nil {
		flow.IP = &IP{
			Source:      grpcFlow.GetIP().GetSource(),
			Destination: grpcFlow.GetIP().GetDestination(),
		}
	}

	// Set L4 information
	if grpcFlow.GetL4() != nil {
		flow.L4 = &L4{}

		if tcp := grpcFlow.GetL4().GetTCP(); tcp != nil {
			flow.L4.TCP = &TCP{
				SourcePort:      tcp.GetSourcePort(),
				DestinationPort: tcp.GetDestinationPort(),
				Bytes:           0, // TCP doesn't have GetBytes method
			}

			// Set TCP flags
			if tcp.GetFlags() != nil {
				flow.L4.TCP.Flags = &TCPFlags{
					SYN: tcp.GetFlags().GetSYN(),
					ACK: tcp.GetFlags().GetACK(),
					FIN: tcp.GetFlags().GetFIN(),
					RST: tcp.GetFlags().GetRST(),
					PSH: tcp.GetFlags().GetPSH(),
					URG: tcp.GetFlags().GetURG(),
				}
			}
		} else if udp := grpcFlow.GetL4().GetUDP(); udp != nil {
			flow.L4.UDP = &UDP{
				SourcePort:      udp.GetSourcePort(),
				DestinationPort: udp.GetDestinationPort(),
				Bytes:           0, // UDP doesn't have GetBytes method
			}
		}
	}

	// Set source endpoint
	if grpcFlow.GetSource() != nil {
		// Convert labels from []string to map[string]string
		labels := make(map[string]string)
		for _, label := range grpcFlow.GetSource().GetLabels() {
			// Parse label in format "key=value"
			if parts := strings.SplitN(label, "=", 2); len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}

		flow.Source = &Endpoint{
			Namespace:   grpcFlow.GetSource().GetNamespace(),
			PodName:     grpcFlow.GetSource().GetPodName(),
			ServiceName: "", // Not available in gRPC flow
			Workload:    "", // Not available in gRPC flow
			Labels:      labels,
		}
	}

	// Set destination endpoint
	if grpcFlow.GetDestination() != nil {
		// Convert labels from []string to map[string]string
		labels := make(map[string]string)
		for _, label := range grpcFlow.GetDestination().GetLabels() {
			// Parse label in format "key=value"
			if parts := strings.SplitN(label, "=", 2); len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}

		flow.Destination = &Endpoint{
			Namespace:   grpcFlow.GetDestination().GetNamespace(),
			PodName:     grpcFlow.GetDestination().GetPodName(),
			ServiceName: "", // Not available in gRPC flow
			Workload:    "", // Not available in gRPC flow
			Labels:      labels,
		}
	}

	// Set L7 information
	if grpcFlow.GetL7() != nil {
		flow.L7 = &L7{}

		// Map L7 types - using string comparison since constants might not match
		l7TypeStr := grpcFlow.GetL7().GetType().String()
		switch l7TypeStr {
		case "HTTP":
			flow.L7.Type = L7Type_HTTP
		case "DNS":
			flow.L7.Type = L7Type_DNS
		case "KAFKA":
			flow.L7.Type = L7Type_KAFKA
		default:
			flow.L7.Type = L7Type_HTTP
		}
	}

	return flow
}

// printAnomalyAlert prints anomaly alert in the requested format
func printAnomalyAlert(alert Alert) {
	// Set timezone to UTC+7 (Vietnam timezone)
	loc, _ := time.LoadLocation("Asia/Ho_Chi_Minh")
	timeInUTC7 := alert.Timestamp.In(loc)

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("Anomaly: DETECTED\n")
	fmt.Printf("Time: %s\n", timeInUTC7.Format("2006-01-02 15:04:05"))
	fmt.Printf("Type: %s\n", alert.Type)

	if alert.FlowData != nil {
		if alert.FlowData.Source != nil {
			fmt.Printf("Source Pod: %s\n", alert.FlowData.Source.PodName)
		} else {
			fmt.Printf("Source Pod: Unknown\n")
		}

		if alert.FlowData.Destination != nil {
			fmt.Printf("Destination Pod: %s\n", alert.FlowData.Destination.PodName)
		} else {
			fmt.Printf("Destination Pod: Unknown\n")
		}

		// Add additional details based on anomaly type
		switch alert.Type {
		case "TRAFFIC_SPIKE":
			fmt.Printf("Details: Traffic spike detected\n")
		case "DDOS_PATTERN":
			fmt.Printf("Details: DDoS pattern detected\n")
		case "HIGH_ERROR_RATE":
			fmt.Printf("Details: High HTTP error rate\n")
		case "ERROR_BURST":
			fmt.Printf("Details: Error burst detected\n")
		}
	}

	fmt.Printf("Severity: %s\n", alert.Severity)
	fmt.Println("=" + strings.Repeat("=", 60))
}

// detectAnomaly handles the anomaly detection functionality
func detectAnomaly(client *HubbleGRPCClient, namespace string) {
	fmt.Println("\n🚨 ANOMALY DETECTION")
	fmt.Println("Press Ctrl+C to return to main menu")
	fmt.Println("")

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create anomaly detector
	config := &Config{
		HubbleServer:  "localhost:4245",
		FlowFilters:   []string{namespace},
		CheckInterval: 5 * time.Second,
		AlertThresholds: AlertThresholds{
			HighBandwidthThreshold:      100000000,
			HighConnectionThreshold:     1000,
			UnusualPortThreshold:        50,
			DropRateThreshold:           5.0,
			TimeWindow:                  60 * time.Second,
			UnusualDestinationThreshold: 100,
		},
		LogLevel: "info",
	}

	detector := NewAnomalyDetector(config, logger)

	// Create alert handler
	alertHandler, err := NewAlertHandler(logger, "alerts.log")
	if err != nil {
		fmt.Printf("❌ Failed to create alert handler: %v\n", err)
		return
	}
	defer alertHandler.Close()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start streaming flows for anomaly detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		<-sigChan
		fmt.Println("\n🛑 Stopping anomaly detection...")
		cancel()
	}()

	// Start anomaly detection
	if err := startAnomalyDetection(ctx, client, detector, alertHandler, namespace); err != nil {
		if err == context.Canceled {
			fmt.Println("✅ Anomaly detection stopped")
		} else {
			fmt.Printf("❌ Anomaly detection failed: %v\n", err)
		}
	}
}

// startAnomalyDetection starts the anomaly detection process
func startAnomalyDetection(ctx context.Context, client *HubbleGRPCClient, detector *AnomalyDetector, alertHandler *AlertHandler, namespace string) error {
	fmt.Println("🚀 Starting anomaly detection...")
	fmt.Printf("📋 Monitoring namespace: %s\n", namespace)
	fmt.Println("")

	// Create Hubble observer client
	observerClient := client.GetObserverClient()
	if observerClient == nil {
		return fmt.Errorf("failed to get observer client")
	}

	// Create flow request for streaming
	req := &observer.GetFlowsRequest{
		Follow: true, // Stream flows continuously
	}

	// Add namespace filter
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
	stream, err := observerClient.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start flow streaming: %v", err)
	}

	flowCount := 0

	// Start alert processing goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case alert := <-detector.GetAlertChannel():
				// Print anomaly in the requested format
				printAnomalyAlert(alert)
				// Also handle alert (save to file)
				alertHandler.HandleAlert(alert)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Receive flow from stream
			response, err := stream.Recv()
			if err != nil {
				return fmt.Errorf("failed to receive flow: %v", err)
			}

			flowCount++

			// Convert gRPC flow to our Flow struct
			flow := convertGRPCFlowToFlow(response.GetFlow())
			if flow != nil {
				// Process flow with anomaly detector (silent processing)
				detector.ProcessFlow(ctx, flow)
			}

			// Only print progress every 1000 flows (less verbose)
			if flowCount%1000 == 0 {
				fmt.Printf("📊 Monitoring... Processed %d flows (silent mode)\n", flowCount)
			}
		}
	}
}
