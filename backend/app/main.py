"""
ThreatVision - SOC SIEM-like Platform
FastAPI entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import logs, alerts, rules, ml
from app.core.database import engine, Base
from app.services.rule_engine import seed_default_rules
from app.core.database import SessionLocal

Base.metadata.create_all(bind=engine)

# Seed default detection rules on startup
db = SessionLocal()
seed_default_rules(db)
db.close()

app = FastAPI(
    title="ThreatVision API",
    description="SOC Platform - Threat Detection & Analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router,   prefix="/api/logs",   tags=["Logs"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(rules.router,  prefix="/api/rules",  tags=["Rules"])
app.include_router(ml.router,     prefix="/api/ml",     tags=["ML Detector"])

@app.get("/")
def health_check():
    return {"status": "ThreatVision operational", "version": "1.0.0"}
