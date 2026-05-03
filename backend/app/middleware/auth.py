"""
Middleware d'authentification par API key pour les endpoints owner.
"""
from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.db.rds import get_session, Owner

API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)


def get_current_owner(api_key: str = Security(API_KEY_HEADER)):
    """
    Dépendance FastAPI — vérifie l'API key et retourne l'owner.
    Utilisation : ajouter `owner: Owner = Depends(get_current_owner)` dans un endpoint.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="UNAUTHORIZED: Authorization header required"
        )

    # Supprimer le préfixe "Bearer " si présent
    key = api_key.replace("Bearer ", "").strip()

    # Chercher l'owner en base
    session = get_session()
    try:
        owner = session.query(Owner).filter(Owner.api_key == key).first()
        if not owner:
            raise HTTPException(
                status_code=401,
                detail="UNAUTHORIZED: Invalid API key"
            )
        return owner
    finally:
        session.close()