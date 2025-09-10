#!/bin/bash

echo "Starting Hubble Anomaly Detector Demo..."
echo ""
echo "This demo will run the anomaly detector in mock mode"
echo "Press Ctrl+C to stop"
echo ""

./hubble-anomaly-detector --log-level=debug --hubble-server=localhost:4245 --alert-log=demo-alerts.log
