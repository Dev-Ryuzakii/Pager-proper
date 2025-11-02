#!/bin/bash

# FastAPI Mobile Backend Startup Script
# Starts the FastAPI server for mobile app integration

echo "🚀 Starting SecureChat Pro FastAPI Backend"
echo "=" * 50

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment: $VIRTUAL_ENV"
else
    echo "⚠️  Warning: No virtual environment detected"
    echo "   Recommend activating venv first: source .venv/bin/activate"
fi

# Check if FastAPI is installed
python -c "import fastapi" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ FastAPI installed"
else
    echo "❌ FastAPI not found. Installing..."
    pip install -r requirements_fastapi.txt
fi

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

echo ""
echo "📱 FastAPI Mobile Backend Features:"
echo "   🔐 JWT Authentication"
echo "   💬 Offline Messaging"
echo "   👥 Contact Management"
echo "   🔒 End-to-End Encryption Integration"
echo "   📊 Real-time API Documentation"
echo ""

echo "🌐 Starting server on http://localhost:8001"
echo "📖 API Documentation: http://localhost:8001/api/docs"
echo "📚 Alternative Docs: http://localhost:8001/api/redoc"
echo ""

echo "Press Ctrl+C to stop the server"
echo ""

# Start the FastAPI server
python fastapi_mobile_backend.py