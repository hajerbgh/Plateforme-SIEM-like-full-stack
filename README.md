# ThreatVision — SOC SIEM-like Platform

> A full-stack Security Operations Center platform for real-time threat detection, log analysis, and anomaly detection — built with FastAPI, React, and Machine Learning.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![React](https://img.shields.io/badge/React-18-61DAFB)
![scikit-learn](https://img.shields.io/badge/ML-IsolationForest-orange)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)

---

## What is ThreatVision?

ThreatVision is a SIEM-like platform that ingests network and system logs, detects threats using a **rule engine** and **machine learning**, and presents everything in a professional SOC dashboard — similar to a lightweight Splunk or Elastic SIEM.

It covers the full SOC analyst workflow:
**Log Ingestion → Rule-based Detection → ML Anomaly Detection → Alert Triage → IOC Lookup**

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Frontend  (React + Vite)           │
│  Dashboard · Alerts · Logs · Rules · ML · IOC  │
└────────────────────┬────────────────────────────┘
                     │  REST API
┌────────────────────▼────────────────────────────┐
│              Backend  (FastAPI)                 │
│  Log Ingestion · Rule Engine · ML Detector     │
│  Alerts API  · Rules API  · ML API             │
└────────────┬────────────────────────────────────┘
             │
        SQLite (dev) / PostgreSQL (prod)
        + Isolation Forest model (.pkl)
```

---

## Features

| Module | Description |
|---|---|
| **Log Ingestion** | Single log, bulk JSON, CSV upload, or attack simulation |
| **Rule Engine** | 6 built-in detection rules (Brute Force, Port Scan, SQLi, XSS, RCE, Path Traversal) |
| **ML Detector** | Isolation Forest anomaly detection — catches unknown threats with no signature |
| **Alert Manager** | Full triage lifecycle: OPEN → INVESTIGATING → RESOLVED / FALSE_POSITIVE |
| **MITRE ATT&CK** | Every alert mapped to a MITRE tactic and technique (T1110, T1046, T1190...) |
| **IOC Lookup** | Real-time IP reputation, geolocation, proxy/VPN detection via ip-api.com |
| **Dashboard** | Live stats, severity charts, top attacker IPs, MITRE coverage map |

---

## Tech Stack

**Backend**
- [FastAPI](https://fastapi.tiangolo.com/) — REST API framework
- [SQLAlchemy](https://www.sqlalchemy.org/) — ORM (SQLite for dev, PostgreSQL-ready)
- [scikit-learn](https://scikit-learn.org/) — Isolation Forest anomaly detection
- [Pydantic](https://docs.pydantic.dev/) — Data validation

**Frontend**
- [React 18](https://react.dev/) + [Vite](https://vitejs.dev/)
- [React Router](https://reactrouter.com/) — Client-side routing
- [Recharts](https://recharts.org/) — Charts and data visualization
- [Lucide React](https://lucide.dev/) — Icons
- [Axios](https://axios-http.com/) — HTTP client

**Infrastructure**
- [Docker](https://www.docker.com/) + Docker Compose
- [Nginx](https://nginx.org/) — Frontend production server + API proxy

---

## Project Structure

```
threatvision/
├── docker-compose.yml
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              # FastAPI app entry point
│       ├── core/
│       │   └── database.py      # SQLAlchemy session & engine
│       ├── models/
│       │   └── models.py        # DB tables: LogEntry, Alert, DetectionRule
│       ├── schemas/
│       │   └── schemas.py       # Pydantic request/response schemas
│       ├── api/
│       │   ├── logs.py          # POST /api/logs, GET /api/logs
│       │   ├── alerts.py        # GET /api/alerts, PATCH /api/alerts/{id}
│       │   ├── rules.py         # GET/POST /api/rules, toggle
│       │   └── ml.py            # POST /api/ml/train, /predict, /seed-data
│       ├── services/
│       │   ├── rule_engine.py   # Threshold + Pattern detection rules
│       │   └── ingestion.py     # Log normalization pipeline
│       └── ml/
│           ├── detector.py      # Isolation Forest wrapper
│           └── data_generator.py # Realistic training data generator
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    └── src/
        ├── api.js               # Axios API service layer
        ├── App.jsx              # Router setup
        ├── index.css            # Global design tokens (CSS variables)
        ├── components/
        │   ├── Sidebar.jsx      # Navigation sidebar
        │   └── SeverityBadge.jsx
        └── pages/
            ├── Dashboard.jsx    # Overview stats + charts + MITRE map
            ├── Alerts.jsx       # Split-panel triage interface
            ├── Logs.jsx         # Searchable log table
            ├── Rules.jsx        # Detection rules management
            ├── MLDetector.jsx   # Train model + predict interface
            └── IOCLookup.jsx    # IP reputation lookup
```

---

## Getting Started

### Option 1 — Docker (recommended, one command)

**Requirements:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)

```bash
git clone https://github.com/your-username/threatvision.git
cd threatvision
docker-compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Swagger docs | http://localhost:8000/docs |

To stop: `docker-compose down`
To wipe data: `docker-compose down -v`

---

### Option 2 — Local Development

**Requirements:** Python 3.10+, Node.js 18+

**Backend**

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# API running at http://localhost:8000
```

**Frontend**

```bash
cd frontend
npm install
npm run dev
# UI running at http://localhost:5173
```

---

## First Steps — Guided Walkthrough

Once the app is running, follow this sequence:

**1. Generate attack data**

Go to **Dashboard** → click **"Simuler des attaques"**.

This injects 9 realistic logs (6× SSH brute force, 1× SQL injection, 1× reverse shell) and triggers the rule engine automatically.

**2. Triage alerts**

Go to **Alerts**. You will see:
- `[HIGH]` Brute Force SSH — T1110
- `[CRITICAL]` SQL Injection — T1190
- `[CRITICAL]` Suspicious Command — T1059

Click any alert → update its status (OPEN → INVESTIGATING → RESOLVED) → add analyst notes.

**3. Train the ML model**

Go to **ML Detector**:
1. Click **"Générer les données"** — injects 200 normal logs + 5 hidden anomalies
2. Click **"Entraîner le modèle"** — trains Isolation Forest
3. Use the **"Tester un log"** form to score arbitrary events

**4. Look up an attacker IP**

Go to **IOC Lookup** → enter `203.0.113.99` → see geolocation, ISP, proxy/VPN detection.

**5. Manage detection rules**

Go to **Rules** → toggle rules on/off, see MITRE mappings.

---

## API Reference

The full interactive API documentation is available at **http://localhost:8000/docs** (Swagger UI).

### Key endpoints

```
GET  /                          Health check
POST /api/logs                  Ingest a single log
GET  /api/logs/simulate         Inject attack simulation logs
POST /api/logs/upload/csv       Upload CSV log file
GET  /api/alerts                List alerts (filter by status, severity)
GET  /api/alerts/stats          Dashboard statistics
PATCH /api/alerts/{id}          Update alert status / analyst notes
GET  /api/rules                 List detection rules
PATCH /api/rules/{id}/toggle    Enable / disable a rule
POST /api/ml/seed-data          Generate training data
POST /api/ml/train              Train Isolation Forest
POST /api/ml/predict            Score a log (anomaly or normal?)
GET  /api/ml/status             ML model status
```

---

## How the Detection Works

### Rule Engine

Two types of rules, inspired by Sigma and Wazuh:

**Threshold rules** — count events within a time window:
```
IF count(login_failed, same IP, 60 seconds) >= 5
→ Alert: Brute Force [T1110]
```

**Pattern rules** — regex on the log message:
```
IF message matches r"(UNION\s+SELECT|DROP\s+TABLE|'--)"
→ Alert: SQL Injection [T1190]
```

### ML Anomaly Detection (Isolation Forest)

Isolation Forest detects **unknown threats** with no predefined signature.

Each log is transformed into a 9-feature numeric vector:

| Feature | What it captures |
|---|---|
| `hour_of_day` | Attacks often happen at night |
| `dest_port_rare` | Unusual port = suspicious |
| `event_type_code` | Encoded event category |
| `message_length` | Long messages = potential exfiltration |
| `is_internal_ip` | External IPs are riskier |
| `protocol_code` | Unexpected protocols |
| `has_username` | Auth attempt indicator |
| `ip_last_octet` | Network pattern |
| `src_port_high` | Ephemeral port indicator |

The algorithm builds 100 random decision trees. Points that are **isolated quickly** (few cuts needed) are anomalies — they differ from the learned normal baseline.

Score interpretation:
- `score > 0` → Normal behavior
- `score < 0` → Anomaly (more negative = more suspicious)
- `score < -0.2` → CRITICAL alert

---

## MITRE ATT&CK Coverage

| Rule | Tactic | Technique |
|---|---|---|
| Brute Force SSH/Login | Credential Access | T1110 |
| Port Scan | Discovery | T1046 |
| SQL Injection | Initial Access | T1190 |
| XSS Attempt | Initial Access | T1190 |
| Suspicious Command | Execution | T1059 |
| Sensitive File Access | Credential Access | T1003 |
| ML Anomaly | Unknown / Zero-Day | ML-DETECTED |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./threatvision.db` | Database connection string |

For PostgreSQL in production:
```
DATABASE_URL=postgresql://user:password@db:5432/threatvision
```

---

## Roadmap

- [ ] WebSocket real-time alert streaming
- [ ] AbuseIPDB / VirusTotal API integration for IOC enrichment
- [ ] Automated ML model retraining on a schedule
- [ ] User authentication (JWT)
- [ ] Export alerts to PDF / CSV
- [ ] PostgreSQL support for production deployments
- [ ] GitHub Actions CI/CD pipeline

---

## Built With

This project was built as a final-year engineering project covering:
- Network & Cloud Security (SIEM concepts, rule-based detection)
- Applied Machine Learning (unsupervised anomaly detection)
- Full-stack development (FastAPI + React)
- DevOps (Docker, multi-stage builds, Nginx)
- Cybersecurity frameworks (MITRE ATT&CK, NIST SP 800-61)

---

## License

MIT License — free to use, modify, and distribute.
