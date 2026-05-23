"""
ML Detector — Détection d'anomalies par Isolation Forest

Pourquoi Isolation Forest pour un SOC ?
════════════════════════════════════════
Les règles (Rule Engine) détectent ce qu'ON CONNAÎT déjà (brute force, SQLi...).
Le ML détecte ce qu'ON NE CONNAÎT PAS encore : comportements anormaux sans signature.

Isolation Forest (sklearn) :
  - Algorithme non supervisé → pas besoin de données labellisées "attaque/normal"
  - Principe : isole les points rares (anomalies) plus vite que les points normaux
  - Score entre -1 (anomalie) et +1 (normal)
  - Idéal pour les logs : on entraîne sur du trafic "normal", les écarts = suspectes

Dans un vrai SOC : c'est ce qu'utilisent Darktrace, Vectra AI, AWS GuardDuty
pour détecter des menaces inconnues (zero-day, insider threat).

Pipeline :
  1. Feature extraction  : transformer les logs en vecteurs numériques
  2. Training            : entraîner Isolation Forest sur les logs récents
  3. Prediction          : scorer chaque nouveau log
  4. Alert generation    : si score < seuil → alerte "Anomalie ML détectée"
"""

import os
import json
import pickle
import numpy as np
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.models import LogEntry, Alert, SeverityLevel, AlertStatus


# ─── FEATURE EXTRACTION ───────────────────────────────────────────────────────

# Ports connus légitimes (HTTP, HTTPS, SSH, DNS, SMTP...)
COMMON_PORTS = {80, 443, 22, 53, 25, 21, 3306, 5432, 8080, 8443}

# Types d'événements encodés numériquement
EVENT_TYPE_MAP = {
    "login_success"  : 0,
    "login_failed"   : 1,
    "http_request"   : 2,
    "port_scan"      : 3,
    "command_exec"   : 4,
    "file_access"    : 5,
    "dns_query"      : 6,
    "other"          : 7,
}

# Protocols encodés
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "HTTPS": 4, "other": 5}


def extract_features(log: LogEntry) -> np.ndarray:
    """
    Transforme un LogEntry en vecteur numérique de 9 features.

    Pourquoi ces features ?
    - Le ML ne comprend que les nombres, pas le texte.
    - On encode chaque attribut significatif du log.
    - Ces features capturent les patterns d'une attaque :
      ex: port inhabituel + heure nocturne + gros message = suspect.

    Features extraites :
      [0] hour_of_day       : heure (0-23) — les attaques arrivent souvent la nuit
      [1] dest_port_encoded : 0=port commun, 1=port rare → port scan
      [2] source_port_high  : 1 si port source > 1024 (éphémère)
      [3] event_type_code   : entier selon EVENT_TYPE_MAP
      [4] protocol_code     : entier selon PROTOCOL_MAP
      [5] message_length    : longueur du message — SQLi/XSS = messages longs
      [6] has_username      : 1 si username présent (tentatives auth)
      [7] ip_last_octet     : dernier octet de l'IP source (pattern réseau)
      [8] is_internal_ip    : 1 si IP privée (10.x, 192.168.x, 172.16.x)
    """
    hour = log.timestamp.hour if log.timestamp else 12

    # Port destination : rare = plus suspect
    dest_port = log.dest_port or 0
    port_encoded = 0 if dest_port in COMMON_PORTS else (1 if dest_port > 0 else 0)

    # Port source éphémère (> 1024 = client dynamique)
    src_port_high = 1 if (log.source_port or 0) > 1024 else 0

    # Type d'événement → entier
    event_code = EVENT_TYPE_MAP.get(log.event_type, 7)

    # Protocol → entier
    proto_code = PROTOCOL_MAP.get(log.protocol or "other", 5)

    # Longueur du message (normalisée)
    msg_len = min(len(log.message or ""), 1000)

    # Présence d'un username (tentatives auth)
    has_user = 1 if log.username else 0

    # Dernier octet IP source (pattern de sous-réseau)
    try:
        ip_last = int((log.source_ip or "0.0.0.0").split(".")[-1])
    except Exception:
        ip_last = 0

    # IP interne (RFC 1918)
    src_ip = log.source_ip or ""
    is_internal = 1 if (
        src_ip.startswith("10.") or
        src_ip.startswith("192.168.") or
        src_ip.startswith("172.")
    ) else 0

    return np.array([
        hour, port_encoded, src_port_high, event_code,
        proto_code, msg_len, has_user, ip_last, is_internal
    ], dtype=float)


# ─── MODÈLE ───────────────────────────────────────────────────────────────────

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")


class AnomalyDetector:
    """
    Wrapper autour de sklearn IsolationForest.

    Cycle de vie :
      1. train(logs)   → entraîne et sauvegarde le modèle
      2. predict(log)  → retourne (is_anomaly: bool, score: float)
      3. analyze(log)  → prédit + crée une alerte si anomalie
    """

    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        """Charge le modèle sauvegardé s'il existe."""
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)

    def _save_model(self):
        """Persiste le modèle entraîné sur disque."""
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

    @property
    def is_trained(self) -> bool:
        return self.model is not None

    def train(self, db: Session, days: int = 7) -> dict:
        """
        Entraîne Isolation Forest sur les logs des N derniers jours.

        Paramètres IsolationForest :
          - n_estimators=100  : 100 arbres d'isolation (plus = plus précis)
          - contamination=0.05: on suppose 5% d'anomalies dans les données d'entraînement
          - random_state=42   : reproductibilité

        Retourne les métriques d'entraînement.
        """
        from sklearn.ensemble import IsolationForest

        since = datetime.utcnow() - timedelta(days=days)
        logs  = db.query(LogEntry).filter(LogEntry.timestamp >= since).all()

        if len(logs) < 10:
            return {"error": f"Pas assez de logs ({len(logs)}). Minimum : 10."}

        # Construire la matrice X (n_samples × 9 features)
        X = np.array([extract_features(log) for log in logs])

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,   # 5% de contamination supposée
            random_state=42,
            n_jobs=-1             # utilise tous les CPUs
        )
        self.model.fit(X)
        self._save_model()

        # Évaluation sur les données d'entraînement
        scores    = self.model.decision_function(X)  # score continu
        preds     = self.model.predict(X)             # -1=anomalie, +1=normal
        n_anomalies = int((preds == -1).sum())

        return {
            "status"         : "Modèle entraîné",
            "logs_used"      : len(logs),
            "n_anomalies_found": n_anomalies,
            "anomaly_rate"   : round(n_anomalies / len(logs) * 100, 2),
            "score_mean"     : round(float(scores.mean()), 4),
            "score_min"      : round(float(scores.min()), 4),
        }

    def predict(self, log: LogEntry) -> tuple[bool, float]:
        """
        Prédit si un log est une anomalie.

        Retourne :
          (True, score)  si anomalie  (score < 0)
          (False, score) si normal    (score >= 0)

        Le score Isolation Forest :
          < 0   → anomalie (plus négatif = plus anormal)
          ≈ 0   → frontière
          > 0   → comportement normal
        """
        if not self.is_trained:
            return False, 0.0

        features = extract_features(log).reshape(1, -1)
        score    = float(self.model.decision_function(features)[0])
        pred     = self.model.predict(features)[0]  # -1 ou +1

        return (pred == -1), score

    def analyze(self, log: LogEntry, db: Session) -> Alert | None:
        """
        Analyse un log et crée une alerte si anomalie détectée.
        Appelé après le Rule Engine pour couvrir les menaces inconnues.
        """
        if not self.is_trained:
            return None

        is_anomaly, score = self.predict(log)

        if not is_anomaly:
            return None

        # Sévérité selon le score (plus négatif = plus critique)
        if score < -0.2:
            severity = SeverityLevel.CRITICAL
        elif score < -0.1:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.MEDIUM

        alert = Alert(
            title       = f"Anomalie ML détectée — {log.source_ip}",
            description = (
                f"Comportement inhabituel détecté par Isolation Forest. "
                f"Score d'anomalie : {score:.4f} (seuil : 0). "
                f"Événement : {log.event_type} depuis {log.source_ip}. "
                f"Ce comportement dévie significativement du trafic normal observé."
            ),
            severity        = severity,
            status          = AlertStatus.OPEN,
            rule_name       = "ML:IsolationForest",
            source_ip       = log.source_ip,
            mitre_tactic    = "Unknown / Zero-Day",
            mitre_technique = "ML-DETECTED",
            log_entry_id    = log.id,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert


# Singleton partagé dans toute l'application
detector = AnomalyDetector()
