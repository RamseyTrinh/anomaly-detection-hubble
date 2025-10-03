package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	// Parse command line flags
	var (
		hubbleServer = flag.String("hubble-server", "localhost:4245", "Hubble server address")
		showVersion  = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("Hubble Anomaly Detector v1.0.0")
		return
	}

	// Set default namespace
	namespace := "default"

	fmt.Println("Hubble Anomaly Detector")
	fmt.Printf("Connecting to Hubble relay at: %s\n", *hubbleServer)
	fmt.Printf("Using namespace: %s\n", namespace)
	fmt.Println("")

	// Create gRPC client
	client, err := NewHubbleGRPCClient(*hubbleServer)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := client.TestConnection(ctx); err != nil {
		fmt.Printf("Connection test failed: %v\n", err)
		os.Exit(1)
	}
	cancel()

	// Show menu and handle user choice
	showMenu(client, namespace)
}

// showMenu displays the main menu and handles user selection
func showMenu(client *HubbleGRPCClient, namespace string) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n" + strings.Repeat("=", 50))
		fmt.Println("MAIN MENU")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println("1. View Flows")
		fmt.Println("2. Detect Anomaly ")
		fmt.Println("3. Exit")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Print("Chọn option (1-3): ")

		input, _ := reader.ReadString('\n')
		choice := input[:len(input)-1]

		switch choice {
		case "1":
			viewFlows(client, namespace)
		case "2":
			detectAnomaly(client, namespace)
		case "3":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Lựa chọn không hợp lệ. Vui lòng chọn 1, 2, hoặc 3.")
		}
	}
}

// viewFlows handles the flow viewing functionality
func viewFlows(client *HubbleGRPCClient, namespace string) {
	fmt.Println("\nVIEWING FLOWS")
	fmt.Println("Press Ctrl+C to return to main menu")
	fmt.Println("")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start streaming flows
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		<-sigChan
		fmt.Println("\nReturning to main menu...")
		cancel()
	}()

	// Stream flows (view only, no Redis)
	if err := client.StreamFlowsViewOnly(ctx, namespace); err != nil {
		if err == context.Canceled {
			fmt.Println("Flow viewing stopped")
		} else {
			fmt.Printf("Flow streaming failed: %v\n", err)
		}
	}
}

// detectAnomaly handles the anomaly detection functionality
func detectAnomaly(client *HubbleGRPCClient, namespace string) {
	fmt.Println("\nANOMALY DETECTION")
	fmt.Println("Connecting to Redis and starting anomaly detection...")
	fmt.Println("Press Ctrl+C to return to main menu")
	fmt.Println("")

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create config
	config := &Config{}

	// Initialize anomaly detector with Redis
	detector, err := NewAnomalyDetector(config, logger)
	if err != nil {
		fmt.Printf("Failed to initialize anomaly detector: %v\n", err)
		return
	}
	defer detector.Close()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start streaming flows with anomaly detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		<-sigChan
		fmt.Println("\nStopping anomaly detection...")
		cancel()
	}()

	go func() {
		alertChannel := detector.GetRuleEngineAlertChannel()
		for {
			select {
			case alert := <-alertChannel:
				fmt.Printf("\nALERT: [%s] %s - %s\n", alert.Severity, alert.Type, alert.Message)
				if alert.Stats != nil {
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start Redis stats monitoring
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Redis stats removed - not needed anymore
			case <-ctx.Done():
				return
			}
		}
	}()

	fmt.Println("Anomaly detection started!")
	fmt.Println("📊 Monitoring flows and detecting anomalies...")
	fmt.Println("")

	// Start streaming flows to Redis (separate from detection)
	go func() {
		if err := client.StreamFlows(ctx, namespace, detector.GetFlowCache()); err != nil {
			if err == context.Canceled {
				fmt.Println("Flow streaming stopped")
			} else {
				fmt.Printf("Flow streaming failed: %v\n", err)
			}
		}
	}()

	// Wait for context to be cancelled
	<-ctx.Done()
	fmt.Println("Anomaly detection stopped")
}
