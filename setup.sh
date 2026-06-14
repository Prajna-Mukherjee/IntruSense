#!/bin/bash
# =============================================================
# setup.sh - Full project setup script
# Run: bash setup.sh
# =============================================================
set -e

echo "🚀 Setting up AI Threat Detection Platform..."

# 1. Backend virtual environment
echo ""
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

echo "📦 Installing backend dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
deactivate

echo "✅ Backend environment ready."

# 2. Frontend dependencies
echo ""
echo "⚛️  Installing frontend dependencies..."
cd frontend
npm install
cd ..

echo "✅ Frontend ready."

# 3. Create data directory
mkdir -p data

# 4. Check for .env file
echo ""
if [ ! -f backend/.env ]; then
    echo "⚠️  No backend/.env file found."
    echo "   Copy backend/.env.example to backend/.env and fill in your credentials."
    echo "   Then run: bash start.sh"
else
    echo "✅ .env file found."
fi

# 5. Train demo models (optional — only if models don't exist)
echo ""
if [ ! -f backend/models/xgboost_model.pkl ]; then
    echo "🤖 No trained models found. Training demo AI models..."
    source venv/bin/activate
    python scripts/train_models.py
    deactivate
    echo "✅ Models trained."
else
    echo "✅ Trained models already exist — skipping training."
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To start the platform, run: bash start.sh"