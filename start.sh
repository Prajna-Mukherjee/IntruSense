#!/bin/bash
# =============================================================
# start.sh - Start backend and frontend together
# Run: bash start.sh
# =============================================================
echo "🛡️  Starting AI Threat Detection Platform..."

# Start backend in background
echo "🔥 Starting FastAPI backend on port 8000..."
source venv/bin/activate
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
cd ..

sleep 2

# Start frontend
echo "⚛️  Starting React frontend on port 3000..."
cd frontend
npm start &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ Platform is running!"
echo "   Backend:  http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo "   Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both services."

# Trap Ctrl+C to kill both
trap "echo 'Stopping...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; deactivate" INT
wait