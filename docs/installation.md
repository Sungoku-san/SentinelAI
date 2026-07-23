# Installation & Setup Guide

This document describes the manual installation of **SentinelAI** backend, frontend, and database services.

---

## Prerequisites

Ensure the following environments are installed on your server or workstation:
- **Python**: version 3.11 or later.
- **Node.js**: version 18.0 or later (with npm).
- **MongoDB**: Community server (running locally or in a container).
- **Git** (optional).

---

## 1. Database Setup
SentinelAI stores connection transcripts, credentials, scores, and prediction summaries in MongoDB.

### Local Installation
1. Download and install MongoDB Community Server from [MongoDB Website](https://www.mongodb.com/try/download/community).
2. Start the database service:
   - On Windows: Start the service via `services.msc` or run `net start MongoDB`.
   - On Linux/macOS: Run `sudo systemctl start mongod`.

### Docker Alternative
Alternatively, run MongoDB inside a Docker container:
```bash
docker run -d --name sentinelai-mongo -p 27017:27017 mongo:latest
```

---

## 2. Backend Installation

1. Navigate to the backend or project root folder.
2. Install virtual environment and packages:
   ```bash
   python -m venv venv
   # Activate on Linux/macOS:
   source venv/bin/activate
   # Activate on Windows:
   .\venv\Scripts\activate
   
   pip install -r backend/requirements.txt
   ```
3. Initialize the model. SentinelAI needs a serialized Random Forest classifier model to start:
   ```bash
   python backend/scripts/train_ai.py
   ```
   This will train the model using synthetic datasets and write it to `backend/models/threat_model.joblib`.

---

## 3. Frontend Compilation

To package the frontend so that FastAPI serves it directly:
1. Navigate to the `frontend/` folder:
   ```bash
   cd frontend
   ```
2. Install Node packages and dependencies:
   ```bash
   npm install
   ```
3. Build the production bundle:
   ```bash
   npm run build
   ```
   This compiles assets into `frontend/dist/`. The FastAPI backend will automatically mount and serve this directory on port `8000`.

---

## 4. Run the System

To start all honeypot emulation ports and the dashboard portal:
```bash
# Return to project root directory
cd ..
# Run the FastAPI entrance script
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Access the panel via: `http://localhost:8000`

---

## 5. Simulating Attacks (Verification)

Once the honeypot is running, you can test it by running our verification simulator script:
```bash
python backend/scripts/generate_traffic.py
```
This script runs automated tests against ports `2222` (SSH), `8080` (HTTP), `2121` (FTP), and `2323` (Telnet). You will see attacks populate on the dashboard in real-time.
