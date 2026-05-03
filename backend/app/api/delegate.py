"""POST /v1/delegate"""
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.crypto.credentials import issue_credential
from app.db.rds import get_session, Agent, Credential, Owner
from app.middleware.auth import get_current_owner

router = APIRouter()


class DelegateRequest(BaseModel):
    agent_did: str
    permissions: List[str]
    expires_in: int = 86400  # Secondes — 24h par défaut


@router.post("/v1/delegate", status_code=201)
def delegate(
    request: DelegateRequest,
    owner: Owner = Depends(get_current_owner),
):
    """Émet un Verifiable Credential signé pour un agent."""
    if not request.permissions:
        raise HTTPException(status_code=422, detail="PERMISSIONS_REQUIRED")
    if request.expires_in <= 0:
        raise HTTPException(status_code=422, detail="INVALID_EXPIRY")

    session = get_session()
    try:
        # Vérifier que l'agent appartient à l'owner
        agent = session.query(Agent).filter(
            Agent.did == request.agent_did,
            Agent.owner_id == owner.id,
        ).first()

        if not agent:
            raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
        if agent.status == "revoked":
            raise HTTPException(status_code=403, detail="AGENT_REVOKED")

        # Émettre le credential
        result = issue_credential(
            owner_did=owner.did,
            owner_private_key_b64=owner.private_key_encrypted,
            agent_did=request.agent_did,
            permissions=request.permissions,
            expires_in_seconds=request.expires_in,
        )

        # Stocker en base
        from datetime import timezone as tz
        expires_at = datetime.fromisoformat(result["expires_at"])

        credential = Credential(
            agent_id=agent.id,
            owner_id=owner.id,
            token=result["token"],
            permissions=request.permissions,
            expires_at=expires_at,
        )
        session.add(credential)
        session.commit()

        return {
            "credential_id": result["credential_id"],
            "token": result["token"],
            "agent_did": request.agent_did,
            "owner_did": owner.did,
            "permissions": request.permissions,
            "issued_at": result["issued_at"],
            "expires_at": result["expires_at"],
        }
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"INTERNAL_ERROR: {str(e)}")
    finally:
        session.close()