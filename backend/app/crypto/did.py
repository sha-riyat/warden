"""
Génération de Decentralized Identifiers (DID) selon le standard W3C.
Format : did:key:z6Mk... (méthode did:key — auto-contenu, sans registre externe)

La méthode did:key encode la clé publique directement dans le DID.
Aucun serveur, aucune blockchain nécessaire pour la résoudre.
"""
import base64
import hashlib


# Préfixe multicodec pour Ed25519 public key : 0xed01
ED25519_MULTICODEC_PREFIX = bytes([0xed, 0x01])

# Alphabet Base58 (Bitcoin/IPFS standard — pas de 0, O, I, l)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode des bytes en Base58."""
    # Compter les zéros initiaux
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break

    # Conversion en entier
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(BASE58_ALPHABET[remainder])

    return "1" * count + "".join(reversed(result))


def public_key_to_did(public_key_b64: str) -> str:
    """
    Convertit une clé publique Ed25519 (base64url) en DID did:key.

    Processus :
    1. Décoder la clé publique depuis base64url
    2. Préfixer avec le code multicodec Ed25519 (0xed01)
    3. Encoder en multibase base58btc (préfixe 'z')
    4. Assembler : did:key:z{encoded}

    Exemple :
    public_key_b64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    → did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
    """
    # Décoder la clé publique
    # Ajouter le padding si nécessaire
    padding = 4 - len(public_key_b64) % 4
    if padding != 4:
        public_key_b64 += "=" * padding
    public_key_bytes = base64.urlsafe_b64decode(public_key_b64)

    # Ajouter le préfixe multicodec Ed25519
    prefixed = ED25519_MULTICODEC_PREFIX + public_key_bytes

    # Encoder en base58btc avec préfixe multibase 'z'
    encoded = _base58_encode(prefixed)

    return f"did:key:z{encoded}"


def generate_did_from_keypair(public_key_b64: str) -> str:
    """
    Interface principale : génère un DID depuis une clé publique base64url.
    Alias de public_key_to_did pour la clarté du code appelant.
    """
    return public_key_to_did(public_key_b64)


def extract_public_key_from_did(did: str) -> str:
    """
    Extrait la clé publique base64url depuis un DID did:key.
    Opération inverse de public_key_to_did.
    Utilisé pour la vérification sans lookup en base de données.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: {did}")

    # Extraire la partie encodée (après 'did:key:z')
    encoded = did[len("did:key:z"):]

    # Décoder depuis base58
    n = 0
    for char in encoded:
        n = n * 58 + BASE58_ALPHABET.index(char)

    # Convertir en bytes
    byte_length = (n.bit_length() + 7) // 8
    decoded_bytes = n.to_bytes(byte_length, "big")

    # Retirer le préfixe multicodec (2 bytes : 0xed, 0x01)
    public_key_bytes = decoded_bytes[2:]

    # Encoder en base64url sans padding
    return base64.urlsafe_b64encode(public_key_bytes).decode().rstrip("=")