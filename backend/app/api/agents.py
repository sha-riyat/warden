"""POST /v1/agents/register — POST /v1/agents/{did}/revoke"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.crypto.keys import generate_keypair
from app.crypto.did import public_key_to_did
from app.db.rds import get_session, Agent, Credential, Owner
from app.middleware.auth import get_current_owner
from app.middleware.audit_log import write_audit_entry

router = APIRouter()


class AgentRegisterRequest(BaseModel):
    name: str
    description: Optional[str] = None
    erc8004_id: Optional[str] = None


@router.post("/v1/agents/register", status_code=201)
def register_agent(
    request: AgentRegisterRequest,
    owner: Owner = Depends(get_current_owner),
):
    """Enregistre un nouvel agent sous l'owner authentifié."""
    session = get_session()
    try:
        # Générer un DID unique pour l'agent
        keypair = generate_keypair()
        did = public_key_to_did(keypair["public_key_b64"])

        agent = Agent(
            did=did,
            owner_id=owner.id,
            name=request.name,
            description=request.description,
            erc8004_id=request.erc8004_id,
        )
        session.add(agent)
        session.commit()

        return {
            "agent_id": str(agent.id),
            "did": did,
            "name": agent.name,
            "owner_did": owner.did,
            "status": "active",
            "created_at": agent.created_at.isoformat(),
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"INTERNAL_ERROR: {str(e)}")
    finally:
        session.close()


@router.get("/v1/agents")
def list_agents(owner: Owner = Depends(get_current_owner)):
    """Liste tous les agents de l'owner authentifié."""
    session = get_session()
    try:
        agents = session.query(Agent).filter(Agent.owner_id == owner.id).all()
        return {
            "agents": [
                {
                    "agent_id": str(a.id),
                    "did": a.did,
                    "name": a.name,
                    "status": a.status,
                    "erc8004_id": a.erc8004_id,
                    "created_at": a.created_at.isoformat(),
                }
                for a in agents
            ],
            "total": len(agents),
        }
    finally:
        session.close()


@router.post("/v1/agents/{agent_did}/revoke")
def revoke_agent(
    agent_did: str,
    owner: Owner = Depends(get_current_owner),
):
    """Révoque un agent — tous ses credentials deviennent invalides immédiatement."""
    session = get_session()
    try:
        # Vérifier que l'agent appartient bien à l'owner
        agent = session.query(Agent).filter(
            Agent.did == agent_did,
            Agent.owner_id == owner.id,
        ).first()

        if not agent:
            raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
        if agent.status == "revoked":
            raise HTTPException(status_code=409, detail="AGENT_ALREADY_REVOKED")

        # Révoquer l'agent
        agent.status = "revoked"

        # Révoquer tous ses credentials actifs
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        credentials = session.query(Credential).filter(
            Credential.agent_id == agent.id,
            Credential.revoked == False,
        ).all()

        for cred in credentials:
            cred.revoked = True
            cred.revoked_at = now

        session.commit()

        # Écrire dans l'audit log
        write_audit_entry(
            owner_did=owner.did,
            agent_did=agent_did,
            action="REVOKED",
            reason="AGENT_REVOKED_BY_OWNER",
        )

        return {
            "revoked": True,
            "agent_did": agent_did,
            "credentials_revoked": len(credentials),
        }
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"INTERNAL_ERROR: {str(e)}")
    finally:
        session.close()