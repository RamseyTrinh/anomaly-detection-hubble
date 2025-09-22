package main

import (
	"time"
)

// Config holds the configuration for the anomaly detector
type Config struct {
	HubbleServer    string          `json:"hubble_server"`
	FlowFilters     []string        `json:"flow_filters"`
	CheckInterval   time.Duration   `json:"check_interval"`
	AlertThresholds AlertThresholds `json:"alert_thresholds"`
	LogLevel        string          `json:"log_level"`
	UseRealClient   bool            `json:"use_real_client"`
}

// AlertThresholds defines thresholds for anomaly detection
type AlertThresholds struct {
	HighBandwidthThreshold       int64         `json:"high_bandwidth_threshold"`       // bytes per second
	HighConnectionThreshold      int           `json:"high_connection_threshold"`      // connections per second
	UnusualPortThreshold         int           `json:"unusual_port_threshold"`         // connections to unusual ports
	DropRateThreshold            float64       `json:"drop_rate_threshold"`            // percentage of dropped packets
	TimeWindow                   time.Duration `json:"time_window"`                    // time window for analysis
	UnusualDestinationThreshold  int           `json:"unusual_destination_threshold"`  // connections to unusual destinations
	NamespaceBandwidthThreshold  int64         `json:"namespace_bandwidth_threshold"`  // bytes per second per namespace
	NamespaceConnectionThreshold int           `json:"namespace_connection_threshold"` // connections per second per namespace
	CrossNamespaceThreshold      int           `json:"cross_namespace_threshold"`      // cross-namespace connections threshold
}
