#!/bin/bash
# =============================================================
# setup.sh - Full project setup script
# Run: bash setup.sh
# =============================================================

set -e
echo "🚀 Setting up AI Threat Detection Platform..."

# 1. Initialize Git
echo ""
echo "📦 Initializing Git repository..."
git init
git add .
git commit -m "Initial commit: AI Threat Detection Platform"

# 2. Backend virtual environment
echo ""
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

echo "📦 Installing backend dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
deactivate

echo "✅ Backend environment ready."

# 3. Frontend dependencies
echo ""
echo "⚛️  Installing frontend dependencies..."
cd frontend
npm install
cd ..

echo "✅ Frontend ready."

# 4. Create data directory
mkdir -p data

# 5. Train demo models
echo ""
echo "🤖 Training demo AI models..."
source venv/bin/activate
python scripts/train_models.py
deactivate

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To start the platform, run: bash start.sh"
