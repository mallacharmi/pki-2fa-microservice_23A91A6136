import base64
import time

import pyotp


def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed to a base32-encoded string.
    """
    # 1. Hex string -> bytes
    seed_bytes = bytes.fromhex(hex_seed)
    # 2. Bytes -> base32 string
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed.

    Args:
        hex_seed: 64-character hex string

    Returns:
        6-digit TOTP code as string (e.g. '123456')
    """
    # Convert hex seed to base32
    base32_seed = _hex_to_base32(hex_seed)

    # TOTP: SHA-1, 30s period, 6 digits (pyotp defaults match spec)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # Generate current code
    code = totp.now()
    return code


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance.

    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: number of periods before/after to accept
                      (default 1 = ±30s)

    Returns:
        True if code is valid, False otherwise
    """
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # valid_window=1 -> current period ±1 period (±30 seconds)
    return bool(totp.verify(code, valid_window=valid_window))


def generate_totp_with_validity(hex_seed: str):
    """
    Helper for /generate-2fa endpoint:
    Returns (code, valid_for_seconds).
    """
    code = generate_totp_code(hex_seed)
    now = int(time.time())
    # seconds remaining in current 30-second window
    valid_for = 30 - (now % 30)
    if valid_for == 30:
        valid_for = 30
    return code, valid_for