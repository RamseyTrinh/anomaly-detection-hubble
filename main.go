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

	fmt.Println("🔍 Hubble Anomaly Detector")
	fmt.Printf("Connecting to Hubble relay at: %s\n", *hubbleServer)
	fmt.Printf("📋 Using namespace: %s\n", namespace)
	fmt.Println("")

	// Create gRPC client
	client, err := NewHubbleGRPCClient(*hubbleServer)
	if err != nil {
		fmt.Printf("❌ Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := client.TestConnection(ctx); err != nil {
		fmt.Printf("❌ Connection test failed: %v\n", err)
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
		fmt.Println("📋 MAIN MENU")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println("1. View Flows - Hiển thị flows real-time")
		fmt.Println("2. Detect Anomaly - Phát hiện bất thường")
		fmt.Println("3. Exit - Thoát chương trình")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Print("Chọn option (1-3): ")

		input, _ := reader.ReadString('\n')
		choice := input[:len(input)-1] // Remove newline

		switch choice {
		case "1":
			viewFlows(client, namespace)
		case "2":
			detectAnomaly(client, namespace)
		case "3":
			fmt.Println("👋 Goodbye!")
			return
		default:
			fmt.Println("❌ Lựa chọn không hợp lệ. Vui lòng chọn 1, 2, hoặc 3.")
		}
	}
}

// viewFlows handles the flow viewing functionality
func viewFlows(client *HubbleGRPCClient, namespace string) {
	fmt.Println("\n🔍 VIEWING FLOWS")
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
		fmt.Println("\n🛑 Returning to main menu...")
		cancel()
	}()

	// Stream flows
	if err := client.StreamFlows(ctx, namespace); err != nil {
		if err == context.Canceled {
			fmt.Println("✅ Flow viewing stopped")
		} else {
			fmt.Printf("❌ Flow streaming failed: %v\n", err)
		}
	}
}
