#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║     🛡  Aegis Security Platform Launcher      ║"
echo "║          Digital Twin Security Scanner         ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Create necessary directories
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/pids"

# Function to check if a port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Stop existing services
echo "🔍 Checking for existing services..."
if [ -f "$PROJECT_DIR/pids/backend.pid" ]; then
    BACKEND_PID=$(cat "$PROJECT_DIR/pids/backend.pid")
    if ps -p $BACKEND_PID > /dev/null 2>&1; then
        echo "🛑 Stopping existing backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID 2>/dev/null
        sleep 2
    fi
    rm -f "$PROJECT_DIR/pids/backend.pid"
fi

if [ -f "$PROJECT_DIR/pids/frontend.pid" ]; then
    FRONTEND_PID=$(cat "$PROJECT_DIR/pids/frontend.pid")
    if ps -p $FRONTEND_PID > /dev/null 2>&1; then
        echo "🛑 Stopping existing frontend (PID: $FRONTEND_PID)..."
        kill $FRONTEND_PID 2>/dev/null
        sleep 2
    fi
    rm -f "$PROJECT_DIR/pids/frontend.pid"
fi

# Kill any processes on ports 5000 and 3000
for port in 5000 3000; do
    if check_port $port; then
        echo "🛑 Killing process on port $port..."
        lsof -ti:$port | xargs kill -9 2>/dev/null
        sleep 1
    fi
done

# Setup Virtual Environment
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to create virtual environment${NC}"
        exit 1
    fi

    # First-time backend dependency install (assumes you have network)
    echo "📦 Installing backend dependencies (first-time setup)..."
    source "$VENV_DIR/bin/activate"
    cd "$PROJECT_DIR/backend"
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to install backend dependencies${NC}"
        deactivate
        exit 1
    fi
    deactivate
else
    echo "✅ Virtual environment already exists, skipping dependency install."
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to activate virtual environment${NC}"
    exit 1
fi
echo "✅ Virtual environment activated: $VIRTUAL_ENV"

# NOTE: Do NOT auto-install backend deps every run (works offline).
# If you ever change requirements.txt, run manually:
#   cd backend && source ../venv/bin/activate && pip install -r requirements.txt

# Start Backend
echo "🚀 Starting Backend Server..."
cd "$PROJECT_DIR/backend"
nohup python app.py > "$PROJECT_DIR/logs/backend.log" 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > "$PROJECT_DIR/pids/backend.pid"
echo "✅ Backend started (PID: $BACKEND_PID)"

# Wait for backend to initialize
echo "⏳ Waiting for backend to initialize..."
BACKEND_READY=false
for i in {1..30}; do
    if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
        BACKEND_READY=true
        break
    fi
    sleep 1
done

if [ "$BACKEND_READY" = false ]; then
    echo -e "${RED}❌ Backend failed to start. Check logs:${NC}"
    echo "   tail -f $PROJECT_DIR/logs/backend.log"
    deactivate
    exit 1
fi

echo -e "${GREEN}✅ Backend is ready!${NC}"

# Check if frontend exists
if [ ! -d "$PROJECT_DIR/frontend" ]; then
    echo -e "${YELLOW}⚠️  Frontend directory not found. Skipping frontend startup.${NC}"
else
    cd "$PROJECT_DIR/frontend"

    # Only install frontend deps if node_modules is missing
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing frontend dependencies (first-time setup)..."
        npm install
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to install frontend dependencies${NC}"
            deactivate
            exit 1
        fi
    else
        echo "✅ Frontend dependencies already installed, skipping npm install."
    fi

    # Start Frontend
    echo "🚀 Starting Frontend Server..."
    nohup npm start > "$PROJECT_DIR/logs/frontend.log" 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > "$PROJECT_DIR/pids/frontend.pid"
    echo "✅ Frontend started (PID: $FRONTEND_PID)"
fi

# Deactivate venv (backend process already running in background)
deactivate

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║          🎉 Platform Started Successfully      ║"
echo "╠════════════════════════════════════════════════╣"
echo "║  Backend:  http://localhost:5000              ║"
echo "║  Frontend: http://localhost:3000              ║"
echo "║  API Docs: http://localhost:5000/api/health   ║"
echo "╠════════════════════════════════════════════════╣"
echo "║  📊 View logs:                                ║"
echo "║     Backend:  tail -f logs/backend.log        ║"
echo "║     Frontend: tail -f logs/frontend.log       ║"
echo "║  🛑 Stop services: ./stop.sh                  ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
