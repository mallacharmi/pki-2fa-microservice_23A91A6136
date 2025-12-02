import os
import time
import base64
import hashlib
from typing import Optional

# Cryptography and Key Loading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# TOTP Generation
import pyotp

# FastAPI and utilities
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# --- Configuration Constants ---
PRIVATE_KEY_PATH = "student_private.pem"
SEED_FILE_PATH = "data/seed.txt"
DATA_DIR = "data"

TOTP_PERIOD = 30 # seconds
TOTP_DIGITS = 6
TOTP_ALGORITHM = hashlib.sha1
# -------------------------------

# --- Pydantic Schemas for Request/Response ---

class DecryptRequest(BaseModel):
    """Schema for POST /decrypt-seed request body."""
    encrypted_seed: str

class VerifyRequest(BaseModel):
    """Schema for POST /verify-2fa request body."""
    code: str

class DecryptResponse(BaseModel):
    """Schema for successful POST /decrypt-seed response."""
    status: str = "ok"

class TOTPResponse(BaseModel):
    """Schema for successful GET /generate-2fa response."""
    code: str
    valid_for: int

class VerifyResponse(BaseModel):
    """Schema for successful POST /verify-2fa response."""
    valid: bool

# --- Initialization and Helpers ---

app = FastAPI(title="PKI-Based 2FA Service")

# Key Loading Helper
def load_private_key() -> Optional[rsa.RSAPrivateKey]:
    """Loads the RSA private key from the PEM file."""
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError(f"Private key file not found at {PRIVATE_KEY_PATH}")
        
    try:
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key
    except Exception as e:
        raise Exception(f"Failed to load private key: {e}")

# Decryption Helper (Adapted from decrypt_seed.py)
def decrypt_seed(encrypted_seed_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    """Decrypts base64-encoded encrypted seed using RSA/OAEP."""
    try:
        # 1. Base64 decode
        ciphertext = base64.b64decode(encrypted_seed_b64)
        
        # 2. RSA/OAEP decrypt with SHA-256 (Required parameters)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Decode bytes to UTF-8 string
        hex_seed = plaintext.decode('utf-8')
        
        # 4. Validate: must be 64-character hex string
        if len(hex_seed) != 64 or not all(c in '0123456789abcdef' for c in hex_seed.lower()):
            raise ValueError("Decrypted seed failed validation (not 64-char hex).")
            
        return hex_seed
        
    except Exception as e:
        # Re-raise as a custom exception to be caught by the endpoint handler
        raise Exception(f"Decryption or validation failed: {e}")

# TOTP Helpers (Adapted from totp_generator.py)
def hex_to_base32(hex_seed: str) -> str:
    """Converts the 64-character hex seed into a Base32 encoded string."""
    raw_seed_bytes = bytes.fromhex(hex_seed)
    base32_seed_key = base64.b32encode(raw_seed_bytes).decode('utf-8').strip("=")
    return base32_seed_key.upper()

def get_totp_object(hex_seed: str) -> pyotp.TOTP:
    """Helper function to convert seed and initialize the TOTP object."""
    base32_key = hex_to_base32(hex_seed)
    return pyotp.TOTP(
        base32_key, 
        digits=TOTP_DIGITS, 
        interval=TOTP_PERIOD, 
        digest=TOTP_ALGORITHM
    )
    
def get_hex_seed_from_file() -> str:
    """Checks for and reads the decrypted hex seed from /data/seed.txt."""
    if not os.path.exists(SEED_FILE_PATH):
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    
    with open(SEED_FILE_PATH, "r") as f:
        hex_seed = f.read().strip()
        
    if len(hex_seed) != 64:
        # Should not happen if decryption was successful, but good to check
        raise HTTPException(status_code=500, detail={"error": "Corrupted seed file."})
        
    return hex_seed

# --- API Endpoints ---

@app.post("/decrypt-seed", response_model=DecryptResponse, status_code=200)
async def endpoint_decrypt_seed(request: DecryptRequest):
    """
    Endpoint 1: POST /decrypt-seed
    Decrypts the base64-encoded seed and saves the result to data/seed.txt.
    """
    try:
        # 1. Load private key
        private_key = load_private_key()
        
        # 2. Decrypt and validate seed
        decrypted_seed = decrypt_seed(request.encrypted_seed, private_key)
        
        # 3. Save to /data/seed.txt
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SEED_FILE_PATH, "w") as f:
            f.write(decrypted_seed)
            
        return DecryptResponse(status="ok")
        
    except FileNotFoundError as e:
        # Custom handling for missing private key
        raise HTTPException(status_code=500, detail={"error": f"Internal key error: {str(e)}"})
    except Exception as e:
        # Catch decryption/validation/saving errors
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

@app.get("/generate-2fa", response_model=TOTPResponse, status_code=200)
async def endpoint_generate_2fa():
    """
    Endpoint 2: GET /generate-2fa
    Reads the decrypted seed and generates the current TOTP code.
    """
    # 1. Check if /data/seed.txt exists and read hex seed
    hex_seed = get_hex_seed_from_file()
    
    # 2. Generate TOTP object and code
    totp = get_totp_object(hex_seed)
    current_code = totp.now()
    
    # 3. Calculate remaining seconds in current period
    current_time_s = time.time()
    time_remaining = TOTP_PERIOD - (int(current_time_s) % TOTP_PERIOD)
    
    # 4. Return code and valid_for
    return TOTPResponse(code=current_code, valid_for=time_remaining)

@app.post("/verify-2fa", response_model=VerifyResponse, status_code=200)
async def endpoint_verify_2fa(request: VerifyRequest):
    """
    Endpoint 3: POST /verify-2fa
    Verifies a provided code against the current and adjacent TOTP periods.
    """
    # 1. Validate code is provided (FastAPI/Pydantic handles the missing key implicitly, 
    # but we should check if the code value is empty/invalid if Pydantic allowed it)
    if not request.code or len(request.code) != TOTP_DIGITS or not request.code.isdigit():
        raise HTTPException(status_code=400, detail={"error": "Code must be a 6-digit number"})

    # 2. Check if /data/seed.txt exists and read hex seed
    hex_seed = get_hex_seed_from_file()
    
    # 3. Create TOTP object
    totp = get_totp_object(hex_seed)

    # 4. Verify TOTP code with ±1 period tolerance (default for pyotp.verify if window is specified)
    # The 'valid_window' of 1 means it checks the current, one previous, and one next 30s window.
    is_valid = totp.verify(request.code, valid_window=1)
    
    # 5. Return verification result
    return VerifyResponse(valid=is_valid)

# Ensure the data directory exists on startup
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)