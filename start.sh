#!/bin/bash
# =============================================================
# start.sh — Start IntruSense Platform
# Run: bash start.sh
# =============================================================
set -e

echo "🛡️  Starting IntruSense AI Threat Detection Platform..."
echo ""

# ── 1. Start MongoDB ──────────────────────────────────────────────────────────
echo "🍃 Starting MongoDB..."
if ! sudo systemctl is-active --quiet mongod; then
    sudo systemctl start mongod
    sleep 2
fi
echo "✅ MongoDB running on mongodb://localhost:27017"

# ── 2. Start OpenSearch ───────────────────────────────────────────────────────
echo "🔍 Starting OpenSearch..."
if ! sudo systemctl is-active --quiet opensearch; then
    sudo systemctl start opensearch
    echo "⏳ Waiting for OpenSearch to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:9200 > /dev/null 2>&1; then
            break
        fi
        sleep 2
    done
fi
echo "✅ OpenSearch running on http://localhost:9200"

# ── 3. Check .env exists ──────────────────────────────────────────────────────
if [ ! -f "backend/.env" ]; then
    echo ""
    echo "❌ backend/.env not found."
    echo "   Please run: bash setup.sh first."
    exit 1
fi

# ── 4. Start FastAPI backend ──────────────────────────────────────────────────
echo ""
echo "🔥 Starting FastAPI backend on port 8000..."
source venv/bin/activate
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
cd ..
sleep 3
echo "✅ Backend running on http://localhost:8000"

# ── 5. Start React frontend ───────────────────────────────────────────────────
echo ""
echo "⚛️  Starting React frontend on port 3000..."
cd frontend
npm start &
FRONTEND_PID=$!
cd ..

echo ""
echo "════════════════════════════════════════════════"
echo "  ✅ IntruSense is running!"
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "  Press Ctrl+C to stop all services."
echo "════════════════════════════════════════════════"
echo ""

# Trap Ctrl+C to cleanly shut everything down
trap "echo ''; echo 'Stopping IntruSense...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; deactivate; echo 'Stopped.'" INT
wait