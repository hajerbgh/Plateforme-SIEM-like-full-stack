"""
Routes API - Règles de détection
CRUD complet pour gérer les règles du Rule Engine
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.models import DetectionRule
from app.schemas.schemas import RuleCreate, RuleResponse
from app.services.rule_engine import seed_default_rules

router = APIRouter()


@router.get("/", response_model=List[RuleResponse], summary="Lister toutes les règles")
def get_rules(db: Session = Depends(get_db)):
    return db.query(DetectionRule).all()


@router.post("/", response_model=RuleResponse, summary="Créer une règle personnalisée")
def create_rule(rule_data: RuleCreate, db: Session = Depends(get_db)):
    rule = DetectionRule(**rule_data.dict())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/{rule_id}/toggle", summary="Activer / Désactiver une règle")
def toggle_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
    rule.enabled = 0 if rule.enabled else 1
    db.commit()
    return {"id": rule.id, "name": rule.name, "enabled": bool(rule.enabled)}


@router.post("/seed", summary="Charger les règles par défaut")
def seed_rules(db: Session = Depends(get_db)):
    """Réinitialise les règles par défaut (brute force, SQLi, etc.)"""
    seed_default_rules(db)
    return {"message": "Règles par défaut chargées"}
