#!/bin/bash

# Build the backend server
echo "🔨 Building backend server..."
cd backend
go build -o bin/server .

if [ $? -eq 0 ]; then
    echo "✅ Backend built successfully"
    echo "🚀 Starting server on port 8080..."
    ./bin/server
else
    echo "❌ Build failed"
    exit 1
fi