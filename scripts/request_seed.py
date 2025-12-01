import requests
from pathlib import Path

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

# ✏ REPLACE THIS with your actual student ID from Partnr
STUDENT_ID = "23A91A6136"

# ❗ Use EXACTLY your repo URL (no .git at the end)
GITHUB_REPO_URL = "https://github.com/mallacharmi/pki-2fa-microservice_23A91A6136.git"


def request_seed(student_id: str, github_repo_url: str, api_url: str = API_URL):
    """
    Request encrypted seed from instructor API and save to encrypted_seed.txt
    """
    # 1. Read student public key as PEM text
    public_pem = Path("student_public.pem").read_text(encoding="utf-8")

    # 2. Prepare payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_pem,
    }

    # 3. Send POST request
    resp = requests.post(api_url, json=payload, timeout=20)

    # Raise if HTTP error (4xx/5xx)
    resp.raise_for_status()

    data = resp.json()

    if data.get("status") != "success":
        raise RuntimeError(f"API error: {data}")

    encrypted_seed = data["encrypted_seed"]

    # 5. Save encrypted seed to file (plain text)
    Path("encrypted_seed.txt").write_text(encrypted_seed, encoding="utf-8")
    print("Encrypted seed saved to encrypted_seed.txt")


if __name__ == "__main__":
    request_seed(STUDENT_ID, GITHUB_REPO_URL)