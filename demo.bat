@echo off
echo Starting Hubble Anomaly Detector Demo...
echo.
echo This demo will run the anomaly detector with gRPC client
echo Make sure Hubble server is running on localhost:4245
echo Press Ctrl+C to stop
echo.

hubble-anomaly-detector.exe --log-level=debug --hubble-server=localhost:4245 --alert-log=demo-alerts.log --real-client=true

pause
