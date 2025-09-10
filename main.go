package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	// Parse command line flags
	var (
		configFile    = flag.String("config", "", "Path to configuration file")
		hubbleServer  = flag.String("hubble-server", "localhost:4245", "Hubble server address")
		alertLogFile  = flag.String("alert-log", "alerts.log", "Alert log file path")
		logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		useRealClient = flag.Bool("real-client", true, "Use real Hubble client instead of mock")
		showVersion   = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("Hubble Anomaly Detector v1.0.0")
		return
	}

	// Setup logger
	logger := setupLogger(*logLevel)
	logger.Info("Starting Hubble Anomaly Detector")

	// Load configuration
	config := loadConfig(*configFile, *hubbleServer, *useRealClient, logger)

	// Create alert handler
	alertHandler, err := NewAlertHandler(logger, *alertLogFile)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create alert handler")
	}
	defer alertHandler.Close()

	// Create anomaly detector
	detector := NewAnomalyDetector(config, logger)

	// Create Hubble client
	var hubbleClient interface {
		Close() error
		GetServerStatus(ctx context.Context) error
		StartFlowStreaming(ctx context.Context, detector *AnomalyDetector, flowFilters []string) error
	}

	if config.UseRealClient {
		hubbleClient, err = NewHubbleSimpleClient(config.HubbleServer, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to create simple gRPC Hubble client")
		}
	} else {
		hubbleClient, err = NewHubbleClient(config.HubbleServer, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to create mock Hubble client")
		}
	}
	defer hubbleClient.Close()

	// Test Hubble server connection
	logger.Info("Testing Hubble server connection...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := hubbleClient.GetServerStatus(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to connect to Hubble server")
	}
	cancel()
	logger.Info("Successfully connected to Hubble server")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start alert handler goroutine
	go func() {
		for alert := range detector.GetAlertChannel() {
			alertHandler.HandleAlert(alert)
		}
	}()

	// Start statistics reset goroutine
	go func() {
		ticker := time.NewTicker(config.AlertThresholds.TimeWindow)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				detector.ResetStats()
				logger.Info("Flow statistics reset")
			}
		}
	}()

	// Start flow streaming
	logger.Info("Starting flow streaming...")
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, stopping...")
		cancel()
	}()

	// Start streaming flows
	err = hubbleClient.StartFlowStreaming(ctx, detector, config.FlowFilters)
	if err != nil && err != context.Canceled {
		logger.WithError(err).Error("Flow streaming failed")
	}

	// Print summary
	alertHandler.PrintSummary()
	logger.Info("Hubble Anomaly Detector stopped")
}

// setupLogger configures the logger
func setupLogger(level string) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// Set log level
	switch level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}

// loadConfig loads configuration from file or uses defaults
func loadConfig(configFile, hubbleServer string, useRealClient bool, logger *logrus.Logger) *Config {
	config := DefaultConfig()

	// Override with command line values
	if hubbleServer != "" {
		config.HubbleServer = hubbleServer
	}
	config.UseRealClient = useRealClient

	// TODO: Add configuration file loading if needed
	// For now, we'll use the default configuration with command line overrides

	logger.WithFields(logrus.Fields{
		"hubble_server":   config.HubbleServer,
		"check_interval":  config.CheckInterval,
		"log_level":       config.LogLevel,
		"use_real_client": config.UseRealClient,
	}).Info("Configuration loaded")

	return config
}
