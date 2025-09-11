#!/bin/bash

echo "🔍 Hubble gRPC Client"
echo ""

# Check if Hubble relay is running
if ! nc -z localhost 4245; then
    echo "❌ Hubble relay is not running on localhost:4245"
    echo ""
    echo "Please start Hubble relay first:"
    echo "  cilium hubble enable"
    echo "  cilium hubble port-forward"
    echo ""
    exit 1
fi

echo "✅ Hubble relay is running on localhost:4245"
echo ""

# Build the client
echo "🔨 Building Hubble gRPC client..."
go build -o hubble-grpc-client main_simple.go hubble_grpc_client.go

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"
echo ""

# Run the client
echo "🚀 Starting Hubble gRPC client..."
echo "Press Ctrl+C to stop"
echo ""

./hubble-grpc-client --hubble-server=localhost:4245
