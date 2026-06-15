#!/bin/bash
# =============================================================
# setup.sh — IntruSense Full Setup Script for Ubuntu VM
# Run: bash setup.sh
# =============================================================
set -e

RELEASE_URL="https://github.com/Prajna-Mukherjee/IntruSense/releases/download/v1.0.0"
MITRE_URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

echo "🛡️  IntruSense — AI Threat Detection Platform Setup"
echo "===================================================="
echo ""

# ── 1. System dependencies ────────────────────────────────────────────────────
echo "📦 Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    curl wget git gnupg apt-transport-https \
    software-properties-common ca-certificates \
    lsb-release build-essential

echo "✅ System dependencies installed."

# ── 2. Node.js 18 ────────────────────────────────────────────────────────────
echo ""
echo "⚛️  Installing Node.js 18..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo "✅ Node.js $(node --version) installed."
else
    echo "✅ Node.js already installed: $(node --version)"
fi

# ── 3. MongoDB (local) ────────────────────────────────────────────────────────
echo ""
echo "🍃 Installing MongoDB..."
if ! command -v mongod &> /dev/null; then
    curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
        sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
        https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
        sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
    sudo apt-get update -qq
    sudo apt-get install -y mongodb-org
    echo "✅ MongoDB installed."
else
    echo "✅ MongoDB already installed."
fi

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
echo "✅ MongoDB running on mongodb://localhost:27017"

# ── 4. OpenSearch (local) ─────────────────────────────────────────────────────
echo ""
echo "🔍 Installing OpenSearch..."
if ! command -v opensearch &> /dev/null; then
    # Install Java (OpenSearch requires it)
    sudo apt-get install -y openjdk-17-jdk

    curl -fsSL https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.0/opensearch-2.11.0-linux-x64.tar.gz \
        -o /tmp/opensearch.tar.gz

    sudo mkdir -p /opt/opensearch
    sudo tar -xzf /tmp/opensearch.tar.gz -C /opt/opensearch --strip-components=1
    rm /tmp/opensearch.tar.gz

    # Disable security plugin for local dev (no SSL/auth needed locally)
    sudo bash -c 'echo "plugins.security.disabled: true" >> /opt/opensearch/config/opensearch.yml'
    sudo bash -c 'echo "discovery.type: single-node" >> /opt/opensearch/config/opensearch.yml'

    # Create systemd service for OpenSearch
    sudo tee /etc/systemd/system/opensearch.service > /dev/null <<EOF
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=/opt/opensearch/bin/opensearch
Restart=on-failure
Environment=OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m"
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl start opensearch
    sudo systemctl enable opensearch
    echo "✅ OpenSearch installed and running on http://localhost:9200"
else
    echo "✅ OpenSearch already installed."
    sudo systemctl start opensearch
fi

# Wait for OpenSearch to be ready
echo "⏳ Waiting for OpenSearch to start..."
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        echo "✅ OpenSearch is ready."
        break
    fi
    sleep 2
done

# ── 5. Python virtual environment ─────────────────────────────────────────────
echo ""
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
deactivate
echo "✅ Python environment ready."

# ── 6. Frontend dependencies ──────────────────────────────────────────────────
echo ""
echo "⚛️  Installing frontend dependencies..."
cd frontend
npm install --silent
cd ..
echo "✅ Frontend ready."

# ── 7. Download ML model files from GitHub Releases ──────────────────────────
echo ""
echo "🤖 Downloading pre-trained ML models from GitHub Releases..."
mkdir -p backend/models

MODELS=(
    "xgboost_model.pkl"
    "isolation_forest.pkl"
    "autoencoder.h5"
    "scaler.pkl"
    "label_mapping.pkl"
    "feature_columns.pkl"
)

for model in "${MODELS[@]}"; do
    if [ ! -f "backend/models/$model" ]; then
        echo "   Downloading $model..."
        wget -q --show-progress \
            "$RELEASE_URL/$model" \
            -O "backend/models/$model"
        echo "   ✅ $model downloaded."
    else
        echo "   ✅ $model already exists — skipping."
    fi
done

echo "✅ All models ready."

# ── 8. Download MITRE ATT&CK STIX bundle ─────────────────────────────────────
echo ""
echo "🗺️  Downloading MITRE ATT&CK STIX bundle..."
mkdir -p backend/data

if [ ! -f "backend/data/enterprise-attack.json" ]; then
    wget -q --show-progress \
        "$MITRE_URL" \
        -O "backend/data/enterprise-attack.json"
    echo "✅ MITRE ATT&CK bundle downloaded."
else
    echo "✅ MITRE ATT&CK bundle already exists — skipping."
fi

# ── 9. Generate .env file ─────────────────────────────────────────────────────
echo ""
echo "🔐 Setting up environment configuration..."

if [ ! -f "backend/.env" ]; then
    # Auto-generate a secure JWT secret
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    cat > backend/.env <<EOF
# ── IntruSense Environment Configuration ──────────────────
# Auto-generated by setup.sh on $(date)

# JWT — auto-generated secure secret
JWT_SECRET=$JWT_SECRET

# MongoDB — local instance
MONGO_URI=mongodb://localhost:27017/intrusense

# OpenSearch — local instance
ES_HOST=http://localhost:9200

# Frontend URL
FRONTEND_URL=http://localhost:3000

# CORS
ALLOWED_ORIGINS=http://localhost:3000

# Google OAuth — optional, leave blank to disable
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
EOF

    echo "✅ .env file created with auto-generated JWT secret."
else
    echo "✅ .env file already exists — skipping."
fi

# ── 10. Create frontend .env ──────────────────────────────────────────────────
if [ ! -f "frontend/.env.development" ]; then
    cat > frontend/.env.development <<EOF
REACT_APP_API_URL=http://localhost:8000
EOF
    echo "✅ Frontend .env.development created."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "🎉 Setup complete!"
echo ""
echo "════════════════════════════════════════"
echo "  To start IntruSense run: bash start.sh"
echo "════════════════════════════════════════"
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""