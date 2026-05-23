"""
Service d'ingestion de logs

Responsabilité : parser et normaliser les logs avant stockage.

Dans un vrai SOC, les logs arrivent de partout :
  - Syslog (firewalls, switches, serveurs Linux)
  - Windows Event Log
  - Apache/Nginx access logs
  - AWS CloudTrail
  - Endpoint Detection (EDR)

On normalise tout dans notre format commun (LogEntry)
C'est ce qu'on appelle la "normalisation" dans un SIEM.
"""

import csv
import json
import io
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.models import LogEntry
from app.schemas.schemas import LogEntryCreate
from app.services.rule_engine import RuleEngine


class LogIngestionService:

    def __init__(self, db: Session):
        self.db = db
        self.rule_engine = RuleEngine(db)

    def ingest_single(self, log_data: LogEntryCreate) -> dict:
        """
        Ingère un seul log et déclenche immédiatement l'analyse.
        Utilisé pour les logs en temps réel (WebSocket, agents).
        """
        log_entry = LogEntry(
            timestamp   = log_data.timestamp or datetime.utcnow(),
            source_ip   = log_data.source_ip,
            dest_ip     = log_data.dest_ip,
            source_port = log_data.source_port,
            dest_port   = log_data.dest_port,
            protocol    = log_data.protocol,
            event_type  = log_data.event_type,
            message     = log_data.message,
            raw_log     = log_data.raw_log,
            hostname    = log_data.hostname,
            username    = log_data.username,
        )
        self.db.add(log_entry)
        self.db.commit()
        self.db.refresh(log_entry)

        # Analyse immédiate par le Rule Engine
        alerts = self.rule_engine.analyze_log(log_entry)

        # Analyse ML (si modèle entraîné)
        from app.ml.detector import detector
        ml_alert = detector.analyze(log_entry, self.db)
        if ml_alert:
            alerts.append(ml_alert)

        return {
            "log_id"         : log_entry.id,
            "alerts_created" : len(alerts),
            "alert_ids"      : [a.id for a in alerts]
        }

    def ingest_bulk_json(self, content: str) -> dict:
        """
        Ingère un fichier JSON contenant une liste de logs.
        Format attendu : liste d'objets avec les mêmes champs que LogEntryCreate.
        """
        logs_data = json.loads(content)
        return self._process_bulk(logs_data)

    def ingest_bulk_csv(self, content: str) -> dict:
        """
        Ingère un fichier CSV.
        En-têtes attendus : source_ip, event_type, message, [dest_ip, protocol, ...]
        
        Exemple de ligne CSV :
        192.168.1.10,login_failed,"Authentication failure for user admin",22,TCP
        """
        reader = csv.DictReader(io.StringIO(content))
        logs_data = []
        for row in reader:
            # Nettoyer les clés (trim whitespace)
            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
            logs_data.append(clean_row)
        return self._process_bulk(logs_data)

    def _process_bulk(self, logs_data: list) -> dict:
        """Traitement commun pour l'import en masse"""
        total      = len(logs_data)
        ingested   = 0
        errors     = 0
        total_alerts = 0

        for item in logs_data:
            try:
                log_create = LogEntryCreate(**item)
                result = self.ingest_single(log_create)
                total_alerts += result["alerts_created"]
                ingested += 1
            except Exception as e:
                errors += 1
                continue

        return {
            "total"          : total,
            "ingested"       : ingested,
            "errors"         : errors,
            "alerts_created" : total_alerts
        }
