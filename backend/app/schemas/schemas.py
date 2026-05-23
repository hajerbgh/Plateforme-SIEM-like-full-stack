"""
Schémas Pydantic - Validation des données d'entrée/sortie

Pourquoi Pydantic ?
- FastAPI l'utilise pour valider automatiquement les requêtes HTTP
- Si un champ manque ou a le mauvais type → erreur 422 automatique
- Sépare la couche API de la couche DB (bonne pratique)

Pattern : 
  - *Base    : champs communs
  - *Create  : ce que le client envoie (POST)
  - *Response: ce qu'on retourne au client (GET)
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from app.models.models import SeverityLevel, AlertStatus


# ─── LOG ENTRIES ─────────────────────────────────────────────────────────────

class LogEntryCreate(BaseModel):
    """Schéma pour créer un log (POST /api/logs)"""
    source_ip   : str
    dest_ip     : Optional[str] = None
    source_port : Optional[int] = None
    dest_port   : Optional[int] = None
    protocol    : Optional[str] = None
    event_type  : str
    message     : str
    raw_log     : Optional[str] = None
    hostname    : Optional[str] = None
    username    : Optional[str] = None
    timestamp   : Optional[datetime] = None  # Si absent → now()


class LogEntryResponse(BaseModel):
    """Schéma de réponse pour un log"""
    id          : int
    timestamp   : datetime
    source_ip   : str
    dest_ip     : Optional[str]
    source_port : Optional[int]
    dest_port   : Optional[int]
    protocol    : Optional[str]
    event_type  : str
    message     : str
    hostname    : Optional[str]
    username    : Optional[str]

    class Config:
        from_attributes = True  # Permet de convertir un objet SQLAlchemy en Pydantic


class LogBulkCreate(BaseModel):
    """Pour importer plusieurs logs d'un coup (upload CSV/JSON)"""
    logs: List[LogEntryCreate]


# ─── ALERTS ──────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    """Schéma de réponse pour une alerte"""
    id              : int
    created_at      : datetime
    title           : str
    description     : str
    severity        : SeverityLevel
    status          : AlertStatus
    rule_name       : str
    source_ip       : Optional[str]
    mitre_tactic    : Optional[str]
    mitre_technique : Optional[str]
    analyst_notes   : Optional[str]
    log_entry_id    : Optional[int]

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    """Pour mettre à jour le statut/notes d'une alerte (PATCH /api/alerts/{id})"""
    status        : Optional[AlertStatus] = None
    analyst_notes : Optional[str] = None


# ─── RULES ───────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name        : str
    description : str
    severity    : SeverityLevel
    condition   : str  # "threshold" | "pattern" | "anomaly"
    parameters  : str  # JSON string
    mitre_tactic    : Optional[str] = None
    mitre_technique : Optional[str] = None


class RuleResponse(RuleCreate):
    id         : int
    enabled    : int
    created_at : datetime

    class Config:
        from_attributes = True


# ─── STATS DASHBOARD ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    """Statistiques pour le dashboard SOC"""
    total_logs     : int
    total_alerts   : int
    open_alerts    : int
    critical_alerts: int
    alerts_by_severity : dict
    top_source_ips : List[dict]
