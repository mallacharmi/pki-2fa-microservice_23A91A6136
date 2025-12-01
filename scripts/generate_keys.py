from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size: int = 4096):
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


def main():
    private_pem, public_pem = generate_rsa_keypair()

    Path("student_private.pem").write_bytes(private_pem)
    Path("student_public.pem").write_bytes(public_pem)

    print("Generated:")
    print("- student_private.pem")
    print("- student_public.pem")


if __name__ == "__main__":
    main()