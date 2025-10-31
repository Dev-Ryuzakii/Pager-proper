#!/bin/bash

# Render Startup Script
# This script is used by Render to start the application

echo "🚀 Starting Secure Messaging API on Render"

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Wait for database to be ready (in case of race conditions)
echo "⏳ Waiting for database to be ready..."
sleep 15

# Test database connection
echo "🧪 Testing database connection..."
python test_db_connection.py
if [ $? -eq 0 ]; then
    echo "✅ Database connection test passed"
else
    echo "⚠️  Database connection test failed, but continuing startup..."
fi

# Start the FastAPI server
echo "🔧 Starting FastAPI server..."
python fastapi_mobile_backend_postgresql.py