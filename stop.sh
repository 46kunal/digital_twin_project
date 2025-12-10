#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🛑 Stopping Aegis Security Platform...${NC}"

# Kill backend
if [ -f .backend.pid ]; then
    BACKEND_PID=$(cat .backend.pid)
    kill $BACKEND_PID 2>/dev/null && echo -e "${GREEN}✅ Backend stopped${NC}"
    rm .backend.pid
fi

# Kill frontend
if [ -f .frontend.pid ]; then
    FRONTEND_PID=$(cat .frontend.pid)
    kill $FRONTEND_PID 2>/dev/null && echo -e "${GREEN}✅ Frontend stopped${NC}"
    rm .frontend.pid
fi

# Kill any remaining processes on ports
lsof -ti:5000 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

echo -e "${GREEN}✅ All services stopped${NC}"
