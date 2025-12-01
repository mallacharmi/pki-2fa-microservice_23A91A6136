import os
import sys
from pathlib import Path

# Add project root (folder containing "app" and "scripts") to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from app.crypto_utils import load_private_key, decrypt_seed


def main():
    encrypted_seed_b64 = Path("encrypted_seed.txt").read_text(encoding="utf-8").strip()
    private_key = load_private_key()
    seed_hex = decrypt_seed(encrypted_seed_b64, private_key)
    print("Decrypted seed:", seed_hex)


if __name__ == "__main__":
    main()