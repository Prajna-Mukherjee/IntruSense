# 🖥️ IntruSense — Ubuntu VM Deployment Guide

This guide covers everything needed to run IntruSense on a fresh Ubuntu VM,
exactly like running Snort or Zeek in a local lab environment.

---

## ✅ Prerequisites

- A machine running **Ubuntu 22.04 LTS** (VM or bare metal)
- At least **4GB RAM** (8GB recommended — Isolation Forest is 92MB)
- At least **10GB free disk space**
- Internet connection (for initial setup only)
- Git installed: `sudo apt-get install git`

---

## 🚀 Quick Start (3 commands)

```bash
git clone https://github.com/Prajna-Mukherjee/IntruSense.git
cd IntruSense
bash setup.sh
```

Once setup completes:

```bash
bash start.sh
```

Open your browser and go to:
http://localhost:3000

That is it. The setup script handles everything automatically.

---

## 🔧 What `setup.sh` Does Automatically

| Step | What happens |
|---|---|
| 1 | Installs Python 3, pip, Node.js 18, wget, curl |
| 2 | Installs and starts **MongoDB 7.0** locally |
| 3 | Installs and starts **OpenSearch 2.11** locally |
| 4 | Creates Python virtual environment |
| 5 | Installs all backend Python dependencies |
| 6 | Installs all frontend Node dependencies |
| 7 | Downloads 6 pre-trained ML model files from GitHub Releases |
| 8 | Downloads MITRE ATT&CK STIX bundle from MITRE's official repo |
| 9 | Auto-generates a secure `backend/.env` with local connection strings |
| 10 | Creates `frontend/.env.development` |

---

## 🔧 What `start.sh` Does

| Step | What happens |
|---|---|
| 1 | Starts MongoDB (if not already running) |
| 2 | Starts OpenSearch (if not already running) |
| 3 | Activates Python venv and starts FastAPI backend on port 8000 |
| 4 | Starts React frontend on port 3000 |

Press **Ctrl+C** to cleanly stop all services.

---

## 📁 After Setup — Directory Structure

IntruSense/

├── backend/

│   ├── .env                    ← auto-generated, never commit this

│   ├── models/                 ← downloaded from GitHub Releases

│   │   ├── xgboost_model.pkl

│   │   ├── isolation_forest.pkl

│   │   ├── autoencoder.h5

│   │   ├── scaler.pkl

│   │   ├── label_mapping.pkl

│   │   └── feature_columns.pkl

│   └── data/

│       └── enterprise-attack.json  ← downloaded from MITRE

├── frontend/

│   └── .env.development        ← auto-generated

└── venv/                       ← auto-generated Python environment



---

## 🌐 Service Endpoints

| Service | URL |
|---|---|
| Frontend Dashboard | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Interactive API Docs | http://localhost:8000/docs |
| MongoDB | mongodb://localhost:27017 |
| OpenSearch | http://localhost:9200 |

---

## 🧪 Testing the Platform

1. Open `http://localhost:3000`
2. Register a new account
3. Log in
4. Click **Upload Logs** and upload a CSV file in NSL-KDD format
5. The platform will analyse each row through the ML ensemble
6. Threats will appear in the **Threat Alerts** panel in real time
7. Click any alert to see the **SHAP explanation** and **MITRE ATT&CK mapping**

To generate sample test logs:
```bash
source venv/bin/activate
python scripts/generate_sample_logs.py
```
This creates a `data/sample_logs.csv` file you can upload directly.

---

## ⚙️ Manual Configuration (Optional)

The auto-generated `backend/.env` uses local defaults. If you want to
customise anything, open it:

```bash
nano backend/.env
```

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | auto-generated 32-byte hex | Must be at least 32 chars |
| `MONGO_URI` | mongodb://localhost:27017/intrusense | Local MongoDB |
| `ES_HOST` | http://localhost:9200 | Local OpenSearch |
| `FRONTEND_URL` | http://localhost:3000 | React app URL |
| `ALLOWED_ORIGINS` | http://localhost:3000 | CORS allowed origin |
| `GOOGLE_CLIENT_ID` | blank | Optional Google OAuth |
| `GOOGLE_CLIENT_SECRET` | blank | Optional Google OAuth |

---

## 🛠️ Troubleshooting

**MongoDB not starting:**
```bash
sudo systemctl status mongod
sudo systemctl restart mongod
```

**OpenSearch not starting:**
```bash
sudo systemctl status opensearch
sudo journalctl -u opensearch -n 50
```

**Backend fails with model error:**
```bash
ls backend/models/
# If models are missing, re-run:
bash setup.sh
```

**Port 3000 or 8000 already in use:**
```bash
sudo lsof -i :3000
sudo lsof -i :8000
sudo kill -9 <PID>
```

**Permission denied on setup.sh:**
```bash
chmod +x setup.sh start.sh
bash setup.sh
```

---

## 🔄 Stopping and Restarting

To stop: press **Ctrl+C** in the terminal running `start.sh`

To restart later (no need to run setup.sh again):
```bash
bash start.sh
```

---

## 📝 Notes

- `setup.sh` is idempotent — safe to run multiple times. It skips steps that are already complete.
- All data is stored locally — MongoDB and OpenSearch run entirely on your VM with no cloud dependency after initial setup.
- Google OAuth is optional — leave `GOOGLE_CLIENT_ID` blank in `.env` to disable it. Email/password login works fully without it.