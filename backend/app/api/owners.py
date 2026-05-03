"""POST /v1/owners/register"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from app.crypto.keys import generate_keypair
from app.crypto.did import public_key_to_did
from app.db.rds import get_session, Owner, generate_api_key, create_tables

router = APIRouter()


class OwnerRegisterRequest(BaseModel):
    name: str
    email: EmailStr


@router.post("/v1/owners/register", status_code=201)
def register_owner(request: OwnerRegisterRequest):
    """
    Enregistre un nouveau owner WARDEN.
    Génère automatiquement : DID, paire Ed25519, API key.
    """
    session = get_session()
    try:
        # Vérifier que l'email n'existe pas déjà
        existing = session.query(Owner).filter(Owner.email == request.email).first()
        if existing:
            raise HTTPException(status_code=409, detail="EMAIL_ALREADY_EXISTS")

        # Générer les identités cryptographiques
        keypair = generate_keypair()
        did = public_key_to_did(keypair["public_key_b64"])
        api_key = generate_api_key()

        # Créer l'owner en base
        owner = Owner(
            did=did,
            name=request.name,
            email=request.email,
            public_key=keypair["public_key_b64"],
            private_key_encrypted=keypair["private_key_b64"],  # TODO M3: chiffrer avec KMS
            api_key=api_key,
        )
        session.add(owner)
        session.commit()

        return {
            "owner_id": str(owner.id),
            "did": did,
            "public_key": keypair["public_key_b64"],
            "api_key": api_key,
            "kyc_status": "pending",
            "created_at": owner.created_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"INTERNAL_ERROR: {str(e)}")
    finally:
        session.close()