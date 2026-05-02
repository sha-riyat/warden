"""
Émission et vérification de Verifiable Credentials (VC) encapsulés en JWT.
Standard : W3C Verifiable Credentials + JWT (RFC 7519) + EdDSA (RFC 8037)

Structure du JWT :
- Header  : { alg: "EdDSA", typ: "JWT", kid: "did:key:z...#keys-1" }
- Payload : { iss, sub, jti, iat, exp, vc: { type, credentialSubject } }
- Signature: Ed25519 (64 bytes)
"""
import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.crypto.keys import load_private_key, load_public_key


class CredentialError(Exception):
    """Erreur lors de l'émission ou de la vérification d'un credential."""
    pass


def issue_credential(
    owner_did: str,
    owner_private_key_b64: str,
    agent_did: str,
    permissions: list[str],
    expires_in_seconds: int = 86400,  # 24h par défaut
) -> dict:
    """
    Émet un Verifiable Credential signé par l'owner pour un agent.

    Args:
        owner_did: DID de l'owner (issuer)
        owner_private_key_b64: Clé privée de l'owner en base64url
        agent_did: DID de l'agent (subject)
        permissions: Liste des permissions accordées
        expires_in_seconds: Durée de validité en secondes

    Returns:
        {
            "token": "eyJ...",      # JWT signé
            "credential_id": "uuid",
            "issued_at": "ISO-8601",
            "expires_at": "ISO-8601",
        }
    """
    if not permissions:
        raise CredentialError("Permissions list cannot be empty")
    if expires_in_seconds <= 0:
        raise CredentialError("expires_in must be positive")
    if expires_in_seconds > 31536000:  # 1 an max
        raise CredentialError("expires_in cannot exceed 1 year")

    now = int(time.time())
    credential_id = str(uuid.uuid4())

    # Payload JWT avec structure Verifiable Credential
    payload = {
        # Claims JWT standard
        "iss": owner_did,           # Qui a émis ce credential (l'owner)
        "sub": agent_did,           # Pour qui (l'agent)
        "jti": credential_id,       # Identifiant unique (anti-replay)
        "iat": now,                 # Émis à
        "exp": now + expires_in_seconds,  # Expire à
        # Verifiable Credential W3C
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
            ],
            "type": ["VerifiableCredential", "WardenDelegation"],
            "credentialSubject": {
                "id": agent_did,
                "permissions": permissions,
                "delegatedBy": owner_did,
            },
        },
    }

    # En-tête JWT avec kid pour identifier la clé
    headers = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": f"{owner_did}#keys-1",
    }

    # Charger la clé privée et signer
    private_key = load_private_key(owner_private_key_b64)

    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=headers,
    )

    return {
        "token": token,
        "credential_id": credential_id,
        "issued_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(
            now + expires_in_seconds, tz=timezone.utc
        ).isoformat(),
    }


def verify_credential(
    token: str,
    owner_public_key_b64: str,
    check_revocation: Optional[callable] = None,
) -> dict:
    """
    Vérifie un credential JWT.

    Args:
        token: Le JWT à vérifier
        owner_public_key_b64: Clé publique de l'owner en base64url
        check_revocation: Fonction optionnelle (credential_id) -> bool

    Returns:
        {
            "valid": bool,
            "reason": str | None,  # Si invalide : EXPIRED | REVOKED | INVALID_SIGNATURE | MALFORMED
            "credential_id": str,
            "agent_did": str,
            "owner_did": str,
            "permissions": list,
            "issued_at": str,
            "expires_at": str,
        }
    """
    result = {
        "valid": False,
        "reason": None,
        "credential_id": None,
        "agent_did": None,
        "owner_did": None,
        "permissions": [],
        "issued_at": None,
        "expires_at": None,
    }

    try:
        # Charger la clé publique
        public_key = load_public_key(owner_public_key_b64)

        # Vérifier et décoder le JWT
        # PyJWT vérifie automatiquement : signature, expiration, format
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={
                "verify_exp": True,
                "verify_iat": True,
            },
        )

        credential_id = payload.get("jti")
        agent_did = payload.get("sub")
        owner_did = payload.get("iss")
        vc = payload.get("vc", {})
        permissions = vc.get("credentialSubject", {}).get("permissions", [])

        result.update({
            "credential_id": credential_id,
            "agent_did": agent_did,
            "owner_did": owner_did,
            "permissions": permissions,
            "issued_at": datetime.fromtimestamp(
                payload["iat"], tz=timezone.utc
            ).isoformat(),
            "expires_at": datetime.fromtimestamp(
                payload["exp"], tz=timezone.utc
            ).isoformat(),
        })

        # Vérification de révocation (si fournie)
        if check_revocation and credential_id:
            if check_revocation(credential_id):
                result["reason"] = "REVOKED"
                return result

        result["valid"] = True

    except jwt.ExpiredSignatureError:
        result["reason"] = "EXPIRED"
    except jwt.InvalidSignatureError:
        result["reason"] = "INVALID_SIGNATURE"
    except jwt.DecodeError:
        result["reason"] = "MALFORMED"
    except Exception as e:
        result["reason"] = f"ERROR: {str(e)}"

    return result


def compute_audit_hash(prev_hash: str, entry: dict) -> str:
    """
    Calcule le hash d'une entrée d'audit log.
    Chaque entrée référence le hash de la précédente → chaîne immuable.

    Le hash couvre : prev_hash + credential_id + action + timestamp
    Toute modification d'une entrée invalide tous les hashs suivants.
    """
    content = (
        f"{prev_hash}"
        f"{entry.get('credential_id', '')}"
        f"{entry.get('action', '')}"
        f"{entry.get('timestamp', '')}"
        f"{entry.get('agent_did', '')}"
        f"{entry.get('owner_did', '')}"
    )
    return hashlib.sha256(content.encode()).hexdigest()
