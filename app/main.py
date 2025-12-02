import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .crypto_utils import load_private_key, decrypt_seed
from .totp_utils import generate_totp_with_validity, verify_totp_code

# Path where decrypted seed will be stored (Docker will mount /data volume)
# IMPORTANT: always use the absolute path /data/seed.txt
SEED_FILE_PATH = Path("/data/seed.txt")

app = FastAPI(title="PKI-based 2FA Microservice")


# ---------- Request Models ----------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: Optional[str] = None


# ---------- Small health check (optional but useful) ----------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- Endpoint 1: POST /decrypt-seed ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptSeedRequest):
    """
    Accept base64-encoded encrypted seed, decrypt it using student private key,
    and store 64-char hex seed in /data/seed.txt.
    """
    try:
        private_key = load_private_key()
    except Exception:
        # Treat any key-loading issue as decryption failure for this endpoint
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )

    try:
        seed_hex = decrypt_seed(body.encrypted_seed, private_key)
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )

    try:
        # ensure /data exists, then write seed
        SEED_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SEED_FILE_PATH.write_text(seed_hex + "\n", encoding="utf-8")
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )

    # Success
    return {"status": "ok"}


# ---------- Endpoint 2: GET /generate-2fa ----------

@app.get("/generate-2fa")
def generate_2fa():
    """
    Read seed from /data/seed.txt and return current TOTP code
    with remaining validity seconds.
    """
    if not SEED_FILE_PATH.exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        seed_hex = SEED_FILE_PATH.read_text(encoding="utf-8").strip()
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        code, valid_for = generate_totp_with_validity(seed_hex)
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    return {"code": code, "valid_for": valid_for}


# ---------- Endpoint 3: POST /verify-2fa ----------

@app.post("/verify-2fa")
def verify_2fa(body: Verify2FARequest):
    """
    Verify user-supplied TOTP code with ±1 period tolerance.
    """
    # Missing code → 400
    if body.code is None or body.code.strip() == "":
        return JSONResponse(
            status_code=400,
            content={"error": "Missing code"},
        )

    if not SEED_FILE_PATH.exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        seed_hex = SEED_FILE_PATH.read_text(encoding="utf-8").strip()
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        is_valid = verify_totp_code(seed_hex, body.code, valid_window=1)
    except Exception:
        # On crypto error treat as invalid code but still status 200
        is_valid = False

    return {"valid": bool(is_valid)}