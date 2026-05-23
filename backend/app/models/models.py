"""
Modèles de base de données (tables)

Chaque classe = une table dans la DB.
Chaque attribut = une colonne.

Modèles créés :
  - LogEntry  : un événement brut ingéré (ligne de log)
  - Alert     : une menace détectée par une règle
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Enum, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.core.database import Base


class SeverityLevel(str, enum.Enum):
    """Niveaux de sévérité SOC standard (inspiré des SIEMs réels)"""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    """Cycle de vie d'une alerte dans un SOC"""
    OPEN          = "OPEN"        # Nouvelle, non traitée
    INVESTIGATING = "INVESTIGATING"  # Analyst au travail
    RESOLVED      = "RESOLVED"    # Clôturée
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Fausse alarme


class LogEntry(Base):
    """
    Table : log_entries
    Représente un événement réseau/système brut.
    
    Exemples réels : ligne Apache access.log, Windows Event Log,
    syslog d'un firewall, log d'un switch Cisco...
    """
    __tablename__ = "log_entries"

    id           = Column(Integer, primary_key=True, index=True)
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip    = Column(String(45), index=True)   # IPv4 ou IPv6 (max 45 chars)
    dest_ip      = Column(String(45), nullable=True)
    source_port  = Column(Integer, nullable=True)
    dest_port    = Column(Integer, nullable=True)
    protocol     = Column(String(10), nullable=True)  # TCP, UDP, ICMP...
    event_type   = Column(String(50), index=True)     # login_failed, port_scan...
    message      = Column(Text)                       # Message brut du log
    raw_log      = Column(Text, nullable=True)        # Ligne originale
    hostname     = Column(String(100), nullable=True)
    username     = Column(String(100), nullable=True)

    # Relation : un log peut générer une alerte
    alerts = relationship("Alert", back_populates="log_entry")


class Alert(Base):
    """
    Table : alerts
    Générée quand le Rule Engine détecte une menace dans les logs.
    
    Dans un vrai SOC, ces alertes apparaissent dans le tableau de bord
    et sont assignées aux analysts pour investigation (triage).
    """
    __tablename__ = "alerts"

    id            = Column(Integer, primary_key=True, index=True)
    created_at    = Column(DateTime, default=datetime.utcnow, index=True)
    title         = Column(String(200))              # Ex: "Brute Force détecté"
    description   = Column(Text)
    severity      = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status        = Column(Enum(AlertStatus), default=AlertStatus.OPEN)
    rule_name     = Column(String(100))              # Quelle règle l'a déclenchée
    source_ip     = Column(String(45), nullable=True)
    mitre_tactic  = Column(String(100), nullable=True)  # Ex: "Credential Access"
    mitre_technique = Column(String(50), nullable=True) # Ex: "T1110"
    analyst_notes = Column(Text, nullable=True)      # Notes de l'analyst

    # Clé étrangère vers le log qui a déclenché l'alerte
    log_entry_id  = Column(Integer, ForeignKey("log_entries.id"), nullable=True)
    log_entry     = relationship("LogEntry", back_populates="alerts")


class DetectionRule(Base):
    """
    Table : detection_rules
    Règles de détection (comme les règles Sigma dans les SIEMs réels).
    
    Sigma est un standard open-source pour écrire des règles de détection
    portables entre différents SIEMs (Splunk, ELK, etc.)
    """
    __tablename__ = "detection_rules"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(100), unique=True)
    description = Column(Text)
    enabled     = Column(Integer, default=1)         # 1=actif, 0=désactivé
    severity    = Column(Enum(SeverityLevel))
    condition   = Column(String(50))                 # "threshold", "pattern", "anomaly"
    # Paramètres JSON de la règle (seuil, pattern regex, etc.)
    parameters  = Column(Text)
    mitre_tactic    = Column(String(100), nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
