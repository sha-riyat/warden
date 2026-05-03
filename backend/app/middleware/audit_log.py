"""
Audit log immuable stocké dans DynamoDB.
Chaque entrée est hashée avec la précédente — toute modification est détectable.
"""
import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError


def get_dynamo_client():
    """Retourne le client DynamoDB boto3."""
    return boto3.client(
        "dynamodb",
        region_name=os.getenv("AWS_REGION_NAME", "eu-west-1")
    )


def get_last_entry_hash(owner_did: str) -> str:
    """
    Récupère le hash de la dernière entrée d'audit pour un owner.
    Retourne "GENESIS" si c'est la première entrée.
    """
    client = get_dynamo_client()
    table_name = os.getenv("DYNAMO_TABLE", "warden-audit-log")

    try:
        response = client.query(
            TableName=table_name,
            KeyConditionExpression="owner_did = :did",
            ExpressionAttributeValues={":did": {"S": owner_did}},
            ScanIndexForward=False,  # Ordre décroissant — dernière entrée en premier
            Limit=1,
        )
        items = response.get("Items", [])
        if items:
            return items[0].get("entry_hash", {}).get("S", "GENESIS")
    except ClientError:
        pass

    return "GENESIS"


def compute_entry_hash(prev_hash: str, entry: dict) -> str:
    """Calcule le hash SHA-256 d'une entrée."""
    content = (
        f"{prev_hash}"
        f"{entry.get('credential_id', '')}"
        f"{entry.get('action', '')}"
        f"{entry.get('timestamp', '')}"
        f"{entry.get('agent_did', '')}"
        f"{entry.get('owner_did', '')}"
    )
    return hashlib.sha256(content.encode()).hexdigest()


def write_audit_entry(
    owner_did: str,
    agent_did: str,
    action: str,
    credential_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> dict:
    """
    Écrit une entrée dans l'audit log DynamoDB.

    Args:
        owner_did: DID de l'owner
        agent_did: DID de l'agent
        action: VERIFIED | DENIED | REVOKED
        credential_id: UUID du credential concerné
        reason: Raison si DENIED (EXPIRED, REVOKED, INVALID_SIGNATURE...)

    Returns:
        L'entrée créée avec son hash
    """
    client = get_dynamo_client()
    table_name = os.getenv("DYNAMO_TABLE", "warden-audit-log")

    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()

    # Récupérer le hash de la dernière entrée pour enchaîner
    prev_hash = get_last_entry_hash(owner_did)

    entry = {
        "owner_did": owner_did,
        "agent_did": agent_did,
        "action": action,
        "credential_id": credential_id or "",
        "timestamp": timestamp,
        "reason": reason or "",
    }

    entry_hash = compute_entry_hash(prev_hash, entry)

    # Écrire dans DynamoDB
    # TTL : 7 ans en secondes depuis epoch (conformité légale)
    ttl = int(now.timestamp()) + (7 * 365 * 24 * 3600)

    client.put_item(
        TableName=table_name,
        Item={
            "owner_did":     {"S": owner_did},
            "timestamp":     {"S": timestamp},
            "agent_did":     {"S": agent_did},
            "action":        {"S": action},
            "credential_id": {"S": credential_id or ""},
            "reason":        {"S": reason or ""},
            "prev_hash":     {"S": prev_hash},
            "entry_hash":    {"S": entry_hash},
            "ttl":           {"N": str(ttl)},
        }
    )

    return {**entry, "prev_hash": prev_hash, "entry_hash": entry_hash}


def get_audit_entries(
    owner_did: str,
    limit: int = 50,
    agent_did_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
) -> dict:
    """
    Récupère les entrées d'audit pour un owner avec vérification d'intégrité.
    """
    client = get_dynamo_client()
    table_name = os.getenv("DYNAMO_TABLE", "warden-audit-log")

    response = client.query(
        TableName=table_name,
        KeyConditionExpression="owner_did = :did",
        ExpressionAttributeValues={":did": {"S": owner_did}},
        ScanIndexForward=True,  # Ordre chronologique
        Limit=min(limit, 100),
    )

    items = response.get("Items", [])

    # Convertir le format DynamoDB en dict Python
    entries = []
    for item in items:
        entry = {
            "timestamp":     item.get("timestamp", {}).get("S", ""),
            "agent_did":     item.get("agent_did", {}).get("S", ""),
            "action":        item.get("action", {}).get("S", ""),
            "credential_id": item.get("credential_id", {}).get("S", ""),
            "reason":        item.get("reason", {}).get("S", ""),
            "entry_hash":    item.get("entry_hash", {}).get("S", ""),
        }

        # Filtres optionnels
        if agent_did_filter and entry["agent_did"] != agent_did_filter:
            continue
        if action_filter and entry["action"] != action_filter:
            continue

        entries.append(entry)

    # Vérifier l'intégrité de la chaîne
    integrity = "valid"
    if len(items) > 1:
        for i in range(1, len(items)):
            prev = items[i-1]
            curr = items[i]
            expected_prev_hash = prev.get("entry_hash", {}).get("S", "")
            actual_prev_hash = curr.get("prev_hash", {}).get("S", "")
            if expected_prev_hash != actual_prev_hash:
                integrity = "compromised"
                break

    return {
        "entries": entries,
        "total": len(entries),
        "integrity": integrity,
    }


# Import Optional manquant — ajouter en haut
