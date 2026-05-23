"""
Rule Engine - Moteur de détection de menaces

C'est le COEUR du projet SOC.

Dans un vrai SIEM (Splunk, ELK/SIEM, Wazuh) :
  - Les règles de corrélation analysent les logs en temps réel
  - Dès qu'une condition est remplie → une alerte est créée
  - Ex: "5 échecs de login depuis la même IP en 60 secondes" → Brute Force

Notre Rule Engine supporte 2 types de règles :
  1. THRESHOLD  : X événements du même type / même IP en Y secondes
  2. PATTERN    : Le message contient un mot-clé dangereux (regex)

Règles préconfigurées mappées sur MITRE ATT&CK :
  - T1110 : Brute Force (Credential Access)
  - T1046 : Port Scan (Discovery)
  - T1071 : Commandes suspectes (Command and Control)
  - T1190 : SQLi / XSS (Initial Access)
"""

import json
import re
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.models import LogEntry, Alert, DetectionRule, SeverityLevel, AlertStatus


# ─── RÈGLES PAR DÉFAUT ────────────────────────────────────────────────────────

DEFAULT_RULES = [
    {
        "name": "Brute Force SSH/Login",
        "description": "Détecte plusieurs tentatives de connexion échouées depuis la même IP",
        "severity": "HIGH",
        "condition": "threshold",
        "parameters": json.dumps({
            "event_type": "login_failed",
            "threshold": 5,       # 5 échecs
            "window_seconds": 60  # dans 60 secondes
        }),
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },
    {
        "name": "Port Scan Détecté",
        "description": "Connexions vers plusieurs ports différents depuis la même source",
        "severity": "MEDIUM",
        "condition": "threshold",
        "parameters": json.dumps({
            "event_type": "port_scan",
            "threshold": 10,
            "window_seconds": 30
        }),
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046"
    },
    {
        "name": "Injection SQL Suspectée",
        "description": "Payload SQL injection détecté dans les logs HTTP",
        "severity": "CRITICAL",
        "condition": "pattern",
        "parameters": json.dumps({
            "pattern": r"(UNION\s+SELECT|DROP\s+TABLE|'--|\bOR\b\s+1=1|exec\s*\()",
            "flags": "IGNORECASE"
        }),
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190"
    },
    {
        "name": "XSS Tentative",
        "description": "Payload Cross-Site Scripting détecté",
        "severity": "HIGH",
        "condition": "pattern",
        "parameters": json.dumps({
            "pattern": r"(<script|javascript:|onerror=|onload=|alert\s*\()",
            "flags": "IGNORECASE"
        }),
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190"
    },
    {
        "name": "Commande Système Suspecte",
        "description": "Exécution de commandes dangereuses détectée dans les logs",
        "severity": "CRITICAL",
        "condition": "pattern",
        "parameters": json.dumps({
            "pattern": r"(wget\s+http|curl\s+http|/bin/bash|nc\s+-|chmod\s+777|rm\s+-rf)",
            "flags": "IGNORECASE"
        }),
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059"
    },
    {
        "name": "Accès Fichiers Sensibles",
        "description": "Tentative d'accès à /etc/passwd, /etc/shadow ou fichiers système",
        "severity": "HIGH",
        "condition": "pattern",
        "parameters": json.dumps({
            "pattern": r"(/etc/passwd|/etc/shadow|/etc/sudoers|\.\.\/\.\.\/)",
            "flags": "IGNORECASE"
        }),
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003"
    }
]


# ─── MOTEUR DE DÉTECTION ──────────────────────────────────────────────────────

class RuleEngine:
    """
    Analyse un log entrant et applique toutes les règles actives.
    Retourne la liste des alertes créées.
    """

    def __init__(self, db: Session):
        self.db = db

    def analyze_log(self, log_entry: LogEntry) -> list[Alert]:
        """
        Point d'entrée : analyse un log contre toutes les règles actives.
        Appelé automatiquement à chaque ingestion de log.
        """
        rules = self.db.query(DetectionRule).filter(
            DetectionRule.enabled == 1
        ).all()

        created_alerts = []
        for rule in rules:
            alert = self._apply_rule(rule, log_entry)
            if alert:
                created_alerts.append(alert)

        return created_alerts

    def _apply_rule(self, rule: DetectionRule, log: LogEntry) -> Alert | None:
        """
        Applique une règle sur un log.
        Retourne une Alert si la règle matche, None sinon.
        """
        params = json.loads(rule.parameters)

        if rule.condition == "threshold":
            return self._check_threshold(rule, log, params)
        elif rule.condition == "pattern":
            return self._check_pattern(rule, log, params)
        return None

    def _check_threshold(self, rule: DetectionRule, log: LogEntry, params: dict) -> Alert | None:
        """
        Règle de SEUIL :
        "Si X événements du même type depuis la même IP dans Y secondes → alerte"
        
        Exemple réel : detecter un brute force SSH = 5 login_failed en 60s
        C'est exactement ce que fait fail2ban, Wazuh, etc.
        """
        required_event_type = params.get("event_type")
        
        # Ce log ne correspond pas au type ciblé par la règle
        if log.event_type != required_event_type:
            return None

        threshold       = params.get("threshold", 5)
        window_seconds  = params.get("window_seconds", 60)
        since           = datetime.utcnow() - timedelta(seconds=window_seconds)

        # Compte les logs similaires dans la fenêtre temporelle
        count = self.db.query(func.count(LogEntry.id)).filter(
            LogEntry.source_ip  == log.source_ip,
            LogEntry.event_type == required_event_type,
            LogEntry.timestamp  >= since
        ).scalar()

        if count >= threshold:
            # Vérifie qu'on n'a pas déjà créé cette alerte récemment (anti-doublon)
            existing = self.db.query(Alert).filter(
                Alert.rule_name  == rule.name,
                Alert.source_ip  == log.source_ip,
                Alert.created_at >= since
            ).first()

            if existing:
                return None  # Alerte déjà créée pour cet événement

            return self._create_alert(
                rule      = rule,
                log       = log,
                title     = f"{rule.name} — {log.source_ip}",
                description = (
                    f"{count} événements '{required_event_type}' depuis {log.source_ip} "
                    f"dans les {window_seconds} dernières secondes. "
                    f"Seuil configuré : {threshold}."
                )
            )
        return None

    def _check_pattern(self, rule: DetectionRule, log: LogEntry, params: dict) -> Alert | None:
        """
        Règle de PATTERN (regex) :
        "Si le message contient ce pattern → alerte"
        
        Exemple réel : détecter SQLi dans les logs Apache
        → GET /page?id=1' UNION SELECT username,password FROM users--
        """
        pattern_str = params.get("pattern", "")
        flags_str   = params.get("flags", "")

        re_flags = 0
        if "IGNORECASE" in flags_str:
            re_flags |= re.IGNORECASE

        if re.search(pattern_str, log.message, re_flags):
            return self._create_alert(
                rule      = rule,
                log       = log,
                title     = f"{rule.name} détecté — {log.source_ip}",
                description = (
                    f"Pattern malveillant détecté dans le message : \"{log.message[:200]}\". "
                    f"Source : {log.source_ip}"
                )
            )
        return None

    def _create_alert(self, rule: DetectionRule, log: LogEntry,
                      title: str, description: str) -> Alert:
        """Crée et persiste une alerte en base de données"""
        alert = Alert(
            title           = title,
            description     = description,
            severity        = rule.severity,
            status          = AlertStatus.OPEN,
            rule_name       = rule.name,
            source_ip       = log.source_ip,
            mitre_tactic    = rule.mitre_tactic,
            mitre_technique = rule.mitre_technique,
            log_entry_id    = log.id
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert


# ─── INITIALISATION DES RÈGLES ────────────────────────────────────────────────

def seed_default_rules(db: Session):
    """
    Charge les règles par défaut en DB si elles n'existent pas encore.
    Appelé au démarrage de l'application.
    """
    for rule_data in DEFAULT_RULES:
        exists = db.query(DetectionRule).filter(
            DetectionRule.name == rule_data["name"]
        ).first()
        if not exists:
            rule = DetectionRule(**rule_data)
            db.add(rule)
    db.commit()
