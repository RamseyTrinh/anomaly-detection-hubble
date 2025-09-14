@echo off
echo Starting Hubble Anomaly Detector...
echo.
echo This will run the anomaly detector with real Hubble relay data
echo Make sure Hubble server is running on localhost:4245
echo Press Ctrl+C to stop
echo.

hubble-anomaly-detector.exe --log-level=debug --hubble-server=localhost:4245 --alert-log=alerts.log

pause
