# SentinelAI

**SentinelAI: An AI-Driven Adaptive Honeypot for Real-Time Threat Intelligence and Behavioral Attack Analysis**

SentinelAI is a research-grade, custom-built AI-powered adaptive honeypot designed to attract cyber threats, emulate vulnerable production services, record attacker sessions, classify behavioral patterns using Machine Learning, and dynamically adapt its responses to trap and audit attackers.

It is designed as an original B.Tech/M.Tech capstone engineering project suitable for academic submission and potential IEEE publication.

---

## Key Features

1. **Multi-Protocol Emulators**: Implements custom socket-based protocol emulators for **SSH**, **HTTP**, **FTP**, and **Telnet** without borrowing from existing projects.
2. **AI Threat Intelligence Engine**: Real-time attack classification using an offline/bootstrap trained `RandomForestClassifier` (Scikit-Learn).
3. **Explainable AI (XAI)**: Generates detailed, human-readable explanations of *why* an attack was classified, highlighting input vectors and MITRE ATT&CK patterns.
4. **Behavioral Attack Analysis**: Maps session command lines directly to MITRE ATT&CK tactics (Discovery, Credential Access, Execution, Command and Control, Evasion).
5. **Dynamic Tarpitting & Adaptation**:
   - Slows down connection requests (tarpitting) progressively as authentication failures increase.
   - Automatically traps repeated offenders inside interactive sandboxed mock environments.
   - Serves dynamic fake folder structures (decoys) when directory scanning is detected.
6. **Real-time Administration Dashboard**: Sleek, responsive dark-mode dashboard showing threat logs, system status, active terminals, and configuration options.
7. **Automated Alerting**: Dispatches instant notifications to Telegram Bots and secure email relays (SMTP) on High/Critical threat triggers.
8. **Forensic Reporting**: Generates formatted PDF reports via ReportLab and CSV raw event sheets.

---

## Project Architecture

```
d:\Honey Pot\
├── backend/
│   ├── app/
│   │   ├── main.py                    # Entrance startup
│   │   ├── config/settings.py         # App configuration settings
│   │   ├── database/mongodb.py        # Database connectors
│   │   ├── models/schemas.py          # API validation Pydantic schemas
│   │   ├── controllers/               # Auth, Dashboard, and Reports logic
│   │   ├── services/                  # Protocol emulators, AI, and alert engines
│   │   ├── routers/                   # API endpoint routers
│   │   ├── middleware/                # OAuth2 authentication validation
│   │   └── utils/helpers.py           # Logging, IP geo, and hash helpers
│   ├── scripts/                       # Model training and traffic simulation scripts
│   ├── tests/                         # Unit tests
│   └── requirements.txt
├── frontend/
│   ├── src/                           # React component structure
│   ├── tailwind.config.js             # Styling definitions
│   └── vite.config.js
├── docs/                              # System documentation
├── Dockerfile                         # Monolithic multi-stage container
└── docker-compose.yml                 # DB and App orchestrator
```

---

## Quick Start (Docker Compose)

The easiest way to run the entire project (including database, honeypots, and administration portal) is using Docker Compose:

1. Clone or copy this repository to your target machine.
2. Ensure Docker and Docker Compose are installed.
3. Configure settings inside the `.env` file (e.g. Telegram tokens, SMTP login).
4. Build and start the environment:
   ```bash
   docker-compose up --build
   ```
5. Open your web browser and navigate to `http://localhost:8000`.
6. Log in with the default credentials:
   - **Username**: `mujeeb`
   - **Password**: `12345`

---

## Local Development Setup

To run SentinelAI locally for development:

### 1. Backend Setup
1. Create a Python 3.11+ virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
2. Install Python requirements:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Run the AI training bootstrap script to compile the model:
   ```bash
   python backend/scripts/train_ai.py
   ```
4. Start the FastAPI server:
   ```bash
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

### 2. Frontend Development Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install Node packages:
   ```bash
   npm install
   ```
3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
4. Access the portal on the printed local address (default: `http://localhost:5173`).
