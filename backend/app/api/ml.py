"""
Routes API — ML Detector
Endpoints pour entraîner le modèle et scorer des logs
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.ml.detector import detector, extract_features
from app.models.models import LogEntry
from app.schemas.schemas import LogEntryCreate
import numpy as np

router = APIRouter()


@router.post("/seed-data", summary="Générer des logs d'entraînement réalistes")
def seed_training_data(db: Session = Depends(get_db)):
    """
    Injecte 200 logs normaux + 5 anomalies pour entraîner le modèle.
    Workflow recommandé : seed-data → train → predict
    """
    from app.ml.data_generator import seed_training_data as _seed
    return _seed(db)


@router.post("/train", summary="Entraîner Isolation Forest sur les logs existants")
def train_model(days: int = 7, db: Session = Depends(get_db)):
    """
    Entraîne le modèle sur les logs des N derniers jours.
    À appeler après avoir ingéré suffisamment de logs "normaux".
    """
    result = detector.train(db, days=days)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/status", summary="Statut du modèle ML")
def model_status():
    """Vérifie si le modèle est entraîné et prêt."""
    return {
        "trained"     : detector.is_trained,
        "model_type"  : "IsolationForest" if detector.is_trained else None,
        "ready"       : detector.is_trained,
    }


@router.post("/predict", summary="Scorer un log (anomalie ou normal ?)")
def predict_log(log_data: LogEntryCreate):
    """
    Score un log sans le stocker en DB.
    Utile pour tester le modèle ou pour des pipelines temps réel.
    """
    if not detector.is_trained:
        raise HTTPException(status_code=400, detail="Modèle non entraîné. Lance /ml/train d'abord.")

    # Créer un LogEntry temporaire pour extraire les features
    from app.models.models import LogEntry
    from datetime import datetime
    tmp_log = LogEntry(
        timestamp   = log_data.timestamp or datetime.utcnow(),
        source_ip   = log_data.source_ip,
        dest_ip     = log_data.dest_ip,
        source_port = log_data.source_port,
        dest_port   = log_data.dest_port,
        protocol    = log_data.protocol,
        event_type  = log_data.event_type,
        message     = log_data.message,
        username    = log_data.username,
    )

    is_anomaly, score = detector.predict(tmp_log)
    features = extract_features(tmp_log).tolist()

    return {
        "is_anomaly"   : is_anomaly,
        "score"        : round(score, 4),
        "verdict"      : "ANOMALIE" if is_anomaly else "Normal",
        "severity"     : (
            "CRITICAL" if score < -0.2 else
            "HIGH"     if score < -0.1 else
            "MEDIUM"   if is_anomaly else "—"
        ),
        "features"     : {
            "hour_of_day"      : features[0],
            "dest_port_rare"   : features[1],
            "src_port_high"    : features[2],
            "event_type_code"  : features[3],
            "protocol_code"    : features[4],
            "message_length"   : features[5],
            "has_username"     : features[6],
            "ip_last_octet"    : features[7],
            "is_internal_ip"   : features[8],
        }
    }


@router.post("/analyze-all", summary="Analyser tous les logs non encore scorés")
def analyze_all_logs(db: Session = Depends(get_db)):
    """
    Passe le détecteur ML sur tous les logs existants.
    Utile pour un scan rétroactif après entraînement.
    """
    if not detector.is_trained:
        raise HTTPException(status_code=400, detail="Modèle non entraîné.")

    logs = db.query(LogEntry).all()
    anomalies = []

    for log in logs:
        alert = detector.analyze(log, db)
        if alert:
            anomalies.append({
                "log_id"   : log.id,
                "alert_id" : alert.id,
                "score"    : round(detector.predict(log)[1], 4),
                "source_ip": log.source_ip,
                "event"    : log.event_type,
            })

    return {
        "logs_analyzed"   : len(logs),
        "anomalies_found" : len(anomalies),
        "anomalies"       : anomalies,
    }
