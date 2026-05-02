"""
Tests unitaires pour le module crypto de WARDEN.
Lance avec : pytest tests/test_crypto.py -v
"""
import time
import pytest

from app.crypto.keys import generate_keypair, load_private_key, load_public_key
from app.crypto.did import (
    public_key_to_did,
    extract_public_key_from_did,
    generate_did_from_keypair,
)
from app.crypto.credentials import (
    issue_credential,
    verify_credential,
    compute_audit_hash,
    CredentialError,
)


# ─── Tests des clés ───────────────────────────────────────────────────────────

class TestKeys:
    def test_generate_keypair_returns_two_keys(self):
        keypair = generate_keypair()
        assert "private_key_b64" in keypair
        assert "public_key_b64" in keypair

    def test_generated_keys_are_strings(self):
        keypair = generate_keypair()
        assert isinstance(keypair["private_key_b64"], str)
        assert isinstance(keypair["public_key_b64"], str)

    def test_two_keypairs_are_different(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1["private_key_b64"] != kp2["private_key_b64"]
        assert kp1["public_key_b64"] != kp2["public_key_b64"]

    def test_load_private_key_roundtrip(self):
        keypair = generate_keypair()
        private_key = load_private_key(keypair["private_key_b64"])
        assert private_key is not None

    def test_load_public_key_roundtrip(self):
        keypair = generate_keypair()
        public_key = load_public_key(keypair["public_key_b64"])
        assert public_key is not None


# ─── Tests des DIDs ───────────────────────────────────────────────────────────

class TestDID:
    def test_did_starts_with_did_key(self):
        keypair = generate_keypair()
        did = public_key_to_did(keypair["public_key_b64"])
        assert did.startswith("did:key:z")

    def test_did_is_deterministic(self):
        keypair = generate_keypair()
        did1 = public_key_to_did(keypair["public_key_b64"])
        did2 = public_key_to_did(keypair["public_key_b64"])
        assert did1 == did2

    def test_different_keys_different_dids(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        did1 = public_key_to_did(kp1["public_key_b64"])
        did2 = public_key_to_did(kp2["public_key_b64"])
        assert did1 != did2

    def test_extract_public_key_roundtrip(self):
        keypair = generate_keypair()
        did = public_key_to_did(keypair["public_key_b64"])
        extracted = extract_public_key_from_did(did)
        # Les clés doivent être équivalentes (padding peut différer)
        original = keypair["public_key_b64"].rstrip("=")
        assert extracted == original or extracted.rstrip("=") == original.rstrip("=")

    def test_generate_did_from_keypair(self):
        keypair = generate_keypair()
        did = generate_did_from_keypair(keypair["public_key_b64"])
        assert did.startswith("did:key:z")


# ─── Tests des credentials ────────────────────────────────────────────────────

class TestCredentials:
    @pytest.fixture
    def owner_keypair(self):
        return generate_keypair()

    @pytest.fixture
    def agent_keypair(self):
        return generate_keypair()

    @pytest.fixture
    def owner_did(self, owner_keypair):
        return public_key_to_did(owner_keypair["public_key_b64"])

    @pytest.fixture
    def agent_did(self, agent_keypair):
        return public_key_to_did(agent_keypair["public_key_b64"])

    def test_issue_credential_returns_token(self, owner_keypair, owner_did, agent_did):
        result = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices"],
        )
        assert "token" in result
        assert "credential_id" in result
        assert "issued_at" in result
        assert "expires_at" in result
        assert result["token"].startswith("eyJ")  # JWT commence toujours par eyJ

    def test_verify_valid_credential(self, owner_keypair, owner_did, agent_did):
        issued = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices", "read:contracts"],
        )
        result = verify_credential(
            token=issued["token"],
            owner_public_key_b64=owner_keypair["public_key_b64"],
        )
        assert result["valid"] is True
        assert result["reason"] is None
        assert result["agent_did"] == agent_did
        assert result["owner_did"] == owner_did
        assert "read:invoices" in result["permissions"]

    def test_verify_expired_credential(self, owner_keypair, owner_did, agent_did):
        # Émettre avec expiration de 1 seconde
        issued = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices"],
            expires_in_seconds=1,
        )
        # Attendre que ça expire
        time.sleep(2)
        result = verify_credential(
            token=issued["token"],
            owner_public_key_b64=owner_keypair["public_key_b64"],
        )
        assert result["valid"] is False
        assert result["reason"] == "EXPIRED"

    def test_verify_tampered_token(self, owner_keypair, owner_did, agent_did):
        issued = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices"],
        )
        # Corrompre le token (changer le dernier caractère)
        tampered = issued["token"][:-1] + ("A" if issued["token"][-1] != "A" else "B")
        result = verify_credential(
            token=tampered,
            owner_public_key_b64=owner_keypair["public_key_b64"],
        )
        assert result["valid"] is False
        assert result["reason"] in ["INVALID_SIGNATURE", "MALFORMED"]

    def test_verify_wrong_public_key(self, owner_keypair, owner_did, agent_did):
        issued = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices"],
        )
        # Vérifier avec une mauvaise clé publique
        wrong_keypair = generate_keypair()
        result = verify_credential(
            token=issued["token"],
            owner_public_key_b64=wrong_keypair["public_key_b64"],
        )
        assert result["valid"] is False

    def test_issue_empty_permissions_raises(self, owner_keypair, owner_did, agent_did):
        with pytest.raises(CredentialError):
            issue_credential(
                owner_did=owner_did,
                owner_private_key_b64=owner_keypair["private_key_b64"],
                agent_did=agent_did,
                permissions=[],
            )

    def test_verify_revoked_credential(self, owner_keypair, owner_did, agent_did):
        issued = issue_credential(
            owner_did=owner_did,
            owner_private_key_b64=owner_keypair["private_key_b64"],
            agent_did=agent_did,
            permissions=["read:invoices"],
        )
        # Simuler une révocation
        revoked_ids = {issued["credential_id"]}
        result = verify_credential(
            token=issued["token"],
            owner_public_key_b64=owner_keypair["public_key_b64"],
            check_revocation=lambda cid: cid in revoked_ids,
        )
        assert result["valid"] is False
        assert result["reason"] == "REVOKED"


# ─── Tests du hash chaîné ─────────────────────────────────────────────────────

class TestAuditHash:
    def test_hash_is_deterministic(self):
        entry = {
            "credential_id": "uuid-123",
            "action": "VERIFIED",
            "timestamp": "2026-05-01T14:00:00Z",
            "agent_did": "did:key:z6Mk...",
            "owner_did": "did:key:z6Mk...",
        }
        h1 = compute_audit_hash("prev_hash_abc", entry)
        h2 = compute_audit_hash("prev_hash_abc", entry)
        assert h1 == h2

    def test_different_prev_hash_different_result(self):
        entry = {
            "credential_id": "uuid-123",
            "action": "VERIFIED",
            "timestamp": "2026-05-01T14:00:00Z",
        }
        h1 = compute_audit_hash("hash_a", entry)
        h2 = compute_audit_hash("hash_b", entry)
        assert h1 != h2

    def test_hash_is_sha256_length(self):
        entry = {"credential_id": "x", "action": "VERIFIED", "timestamp": "t"}
        h = compute_audit_hash("prev", entry)
        assert len(h) == 64  # SHA-256 = 64 caractères hex
