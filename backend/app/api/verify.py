"""
POST /v1/verify — endpoint public, le plus critique du système.
Toujours retourne HTTP 200 — valid=true ou valid=false dans le body.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.crypto.credentials import verify_credential
from app.db.rds import get_session, Owner, Credential
from app.middleware.audit_log import write_audit_entry

router = APIRouter()


class VerifyRequest(BaseModel):
    token: str


@router.post("/v1/verify")
def verify(request: VerifyRequest, http_request: Request):
    import jwt as pyjwt

    response_base = {
        "valid": False,
        "reason": None,
        "agent_did": None,
        "owner_did": None,
        "owner_name": None,
        "owner_kyc": None,
        "permissions": [],
        "issued_at": None,
        "expires_at": None,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }

    # Étape 1 — Décoder AVANT d'ouvrir la session DB
    try:
        unverified = pyjwt.decode(
            request.token,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )
        owner_did = unverified.get("iss")
        agent_did = unverified.get("sub")
    except Exception:
        response_base["reason"] = "MALFORMED"
        return response_base

    if not owner_did:
        response_base["reason"] = "MALFORMED"
        return response_base

    # Étape 2 — Ouvrir la session seulement si le token est bien formé
    session = get_session()
    try:
        owner = session.query(Owner).filter(Owner.did == owner_did).first()

        # Étape 3, 4 — Vérifier la signature et l'expiration
        # Étape 5 — Vérifier la révocation
        def check_revocation(credential_id: str) -> bool:
            cred = session.query(Credential).filter(
                Credential.id == credential_id,
                Credential.revoked == True,
            ).first()
            return cred is not None

        result = verify_credential(
            token=request.token,
            owner_public_key_b64=owner.public_key,
            check_revocation=check_revocation,
        )

        response_base.update({
            "agent_did": result.get("agent_did") or agent_did,
            "owner_did": owner_did,
            "owner_name": owner.name,
            "owner_kyc": owner.kyc_status,
            "permissions": result.get("permissions", []),
            "issued_at": result.get("issued_at"),
            "expires_at": result.get("expires_at"),
        })

        action = "VERIFIED" if result["valid"] else "DENIED"
        response_base["valid"] = result["valid"]
        response_base["reason"] = result.get("reason")

        # Étape 6 — Audit log
        _write_audit_safe(
            owner_did=owner_did,
            agent_did=result.get("agent_did") or agent_did or "",
            action=action,
            credential_id=result.get("credential_id"),
            reason=result.get("reason"),
        )

        return response_base

    except Exception as e:
        response_base["reason"] = f"INTERNAL_ERROR: {str(e)}"
        return response_base
    finally:
        session.close()
    return response_base


def _write_audit_safe(owner_did, agent_did, action, credential_id=None, reason=None):
    """Écrit dans l'audit log sans propager les erreurs."""
    try:
        write_audit_entry(
            owner_did=owner_did,
            agent_did=agent_did,
            action=action,
            credential_id=credential_id,
            reason=reason,
        )
    except Exception:
        pass  # L'audit log ne doit jamais bloquer la réponse