"""GET /v1/audit/{owner_did}"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.rds import Owner
from app.middleware.audit_log import get_audit_entries
from app.middleware.auth import get_current_owner

router = APIRouter()


@router.get("/v1/audit/{owner_did}")
def get_audit(
    owner_did: str,
    limit: int = Query(default=50, le=100),
    agent_did: Optional[str] = None,
    action: Optional[str] = None,
    owner: Owner = Depends(get_current_owner),
):
    """Journal d'audit avec vérification d'intégrité de la chaîne de hash."""
    # Un owner ne peut voir que ses propres logs
    if owner.did != owner_did:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    result = get_audit_entries(
        owner_did=owner_did,
        limit=limit,
        agent_did_filter=agent_did,
        action_filter=action,
    )
    return result   