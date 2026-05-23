"""
Routes API - Alertes
Endpoints pour consulter et gérer les alertes SOC
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from app.core.database import get_db
from app.models.models import Alert, SeverityLevel, AlertStatus
from app.schemas.schemas import AlertResponse, AlertUpdate, DashboardStats

router = APIRouter()


@router.get("/", response_model=List[AlertResponse], summary="Lister les alertes")
def get_alerts(
    skip     : int = Query(0, ge=0),
    limit    : int = Query(50, le=200),
    status   : Optional[AlertStatus]   = None,
    severity : Optional[SeverityLevel] = None,
    db       : Session = Depends(get_db)
):
    """Récupère les alertes avec filtres. Triées par date décroissante (les plus récentes en premier)."""
    query = db.query(Alert).order_by(desc(Alert.created_at))
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    return query.offset(skip).limit(limit).all()


@router.get("/stats", response_model=DashboardStats, summary="Stats pour le dashboard")
def get_stats(db: Session = Depends(get_db)):
    """
    Agrégats pour le dashboard SOC :
    - Compteurs par sévérité
    - Top IPs sources
    - Alertes ouvertes vs résolues
    """
    from app.models.models import LogEntry

    total_logs    = db.query(func.count(LogEntry.id)).scalar()
    total_alerts  = db.query(func.count(Alert.id)).scalar()
    open_alerts   = db.query(func.count(Alert.id)).filter(Alert.status == AlertStatus.OPEN).scalar()
    critical      = db.query(func.count(Alert.id)).filter(Alert.severity == SeverityLevel.CRITICAL).scalar()

    # Comptage par sévérité
    severity_counts = {}
    for level in SeverityLevel:
        count = db.query(func.count(Alert.id)).filter(Alert.severity == level).scalar()
        severity_counts[level.value] = count

    # Top 5 IPs les plus actives
    top_ips_query = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .filter(Alert.source_ip != None)
        .group_by(Alert.source_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_ips = [{"ip": ip, "count": count} for ip, count in top_ips_query]

    return DashboardStats(
        total_logs          = total_logs,
        total_alerts        = total_alerts,
        open_alerts         = open_alerts,
        critical_alerts     = critical,
        alerts_by_severity  = severity_counts,
        top_source_ips      = top_ips
    )


@router.get("/{alert_id}", response_model=AlertResponse, summary="Détail d'une alerte")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte non trouvée")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse, summary="Mettre à jour une alerte")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    """
    L'analyst SOC met à jour le statut de l'alerte :
    OPEN → INVESTIGATING → RESOLVED (ou FALSE_POSITIVE)
    Il peut aussi ajouter des notes d'investigation.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte non trouvée")
    if update.status is not None:
        alert.status = update.status
    if update.analyst_notes is not None:
        alert.analyst_notes = update.analyst_notes
    db.commit()
    db.refresh(alert)
    return alert
