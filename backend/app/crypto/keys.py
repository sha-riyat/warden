"""
Gestion des paires de clés Ed25519 pour WARDEN.
Ed25519 : algorithme de signature moderne, rapide, signatures de 64 bytes.
"""
import base64
import json
import os
import boto3
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_keypair() -> dict:
    """
    Génère une nouvelle paire de clés Ed25519.
    Retourne : { private_key_b64, public_key_b64 }
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Sérialisation en base64url (format compact, URL-safe)
    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        "private_key_b64": base64.urlsafe_b64encode(private_bytes).decode(),
        "public_key_b64": base64.urlsafe_b64encode(public_bytes).decode(),
    }


def load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    """Charge une clé privée depuis sa représentation base64url."""
    raw_bytes = base64.urlsafe_b64decode(private_key_b64 + "==")
    return Ed25519PrivateKey.from_private_bytes(raw_bytes)


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    """Charge une clé publique depuis sa représentation base64url."""
    raw_bytes = base64.urlsafe_b64decode(public_key_b64 + "==")
    return Ed25519PublicKey.from_public_bytes(raw_bytes)


def get_secrets_from_aws(secret_name: str) -> dict:
    """
    Récupère les secrets depuis AWS Secrets Manager.
    Utilisé en production Lambda.
    """
    client = boto3.client(
        "secretsmanager",
        region_name=os.getenv("AWS_REGION_NAME", "eu-west-1")
    )
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def get_owner_private_key(owner_did: str, private_key_b64: str) -> Ed25519PrivateKey:
    """
    Récupère la clé privée d'un owner.
    En MVP : la clé est passée directement (stockée en DB chiffrée).
    En M3 : migration vers HSM / clés client-side.
    """
    return load_private_key(private_key_b64)
