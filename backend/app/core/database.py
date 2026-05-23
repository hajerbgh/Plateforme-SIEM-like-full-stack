"""
Configuration de la base de données
SQLAlchemy + PostgreSQL (ou SQLite pour dev local)

Pourquoi SQLAlchemy ?
- ORM = on écrit des classes Python, pas du SQL brut
- Portable : fonctionne avec SQLite (dev) et PostgreSQL (prod)
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# En dev : SQLite (pas besoin d'installer PostgreSQL)
# En prod : changer pour postgresql://user:pass@host/db
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threatvision.db")

engine = create_engine(
    DATABASE_URL,
    # connect_args requis UNIQUEMENT pour SQLite (gestion du multi-threading)
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base dont héritent tous nos modèles (tables)
Base = declarative_base()

def get_db():
    """
    Dependency Injection FastAPI :
    Ouvre une session DB, l'injecte dans la route, puis la ferme automatiquement.
    Utilisé avec : db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
