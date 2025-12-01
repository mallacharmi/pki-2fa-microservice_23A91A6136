import base64
import string
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


STUDENT_PRIVATE_KEY_PATH = Path("student_private.pem")
STUDENT_PUBLIC_KEY_PATH = Path("student_public.pem")
INSTRUCTOR_PUBLIC_KEY_PATH = Path("instructor_public.pem")


def generate_rsa_keypair(key_size: int = 4096) -> Tuple[bytes, bytes]:
    """
    Generate RSA 4096-bit key pair with public exponent 65537.
    Returns (private_pem_bytes, public_pem_bytes)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def load_private_key(path: Path = STUDENT_PRIVATE_KEY_PATH):
    """
    Load the student private key from PEM file.
    """
    with path.open("rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def load_public_key(path: Path):
    """
    Load a public key (student or instructor) from PEM file.
    """
    with path.open("rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )


def is_valid_hex_seed(seed: str) -> bool:
    """
    Validate that seed is a 64-character hex string.
    """
    if len(seed) != 64:
        return False
    allowed = set(string.hexdigits.lower())
    return all(ch in allowed for ch in seed.lower())


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP-SHA256.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object

    Returns:
        64-character hex seed string

    Raises:
        ValueError on any failure.
    """
    # 1. Base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception:
        raise ValueError("Invalid base64 for encrypted seed")

    # 2. RSA/OAEP decrypt with SHA-256, MGF1(SHA-256), label=None
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

    # 3. Decode bytes to UTF-8 string
    try:
        seed_hex = plaintext_bytes.decode("utf-8").strip()
    except Exception:
        raise ValueError("Decrypted seed is not valid UTF-8 text")

    # 4. Validate 64-character hex
    if not is_valid_hex_seed(seed_hex):
        raise ValueError("Decrypted seed is not valid 64-character hex")

    # 5. Return hex seed
    return seed_hex