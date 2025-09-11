package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Parse command line flags
	var (
		hubbleServer   = flag.String("hubble-server", "localhost:4245", "Hubble server address")
		namespace      = flag.String("namespace", "default", "Filter flows by namespace (default: 'default')")
		listNamespaces = flag.Bool("list-namespaces", false, "List all available namespaces")
		showVersion    = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("Hubble gRPC Client v1.0.0")
		return
	}

	if *listNamespaces {
		// Create gRPC client
		client, err := NewHubbleGRPCClient(*hubbleServer)
		if err != nil {
			fmt.Printf("❌ Failed to create client: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.TestConnection(ctx); err != nil {
			fmt.Printf("❌ Connection test failed: %v\n", err)
			os.Exit(1)
		}

		// Get namespaces
		namespaces, err := client.GetNamespaces(ctx)
		if err != nil {
			fmt.Printf("❌ Failed to get namespaces: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("📋 Available namespaces:")
		for i, ns := range namespaces {
			fmt.Printf("  %d. %s\n", i+1, ns)
		}
		return
	}

	fmt.Println("🔍 Hubble gRPC Client")
	fmt.Printf("Connecting to Hubble relay at: %s\n", *hubbleServer)
	fmt.Printf("📋 Filtering flows for namespace: %s\n", *namespace)
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

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start streaming flows
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		<-sigChan
		fmt.Println("\n🛑 Received shutdown signal, stopping...")
		cancel()
	}()

	// Stream flows
	if err := client.StreamFlows(ctx, *namespace); err != nil {
		fmt.Printf("❌ Flow streaming failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Hubble gRPC Client stopped")
}
