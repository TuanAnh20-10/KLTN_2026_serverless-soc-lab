import hashlib
import hmac
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from urllib.parse import quote

import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.cloud import securitycenter_v1
from dotenv import load_dotenv


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

IAM_API_BASE = "https://iam.googleapis.com/v1"

load_dotenv()


def _load_repo_env() -> None:
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        env_path = parent / ".env"
        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=False)
            break


_load_repo_env()


def _require_query_arg(request, name: str) -> str:
    value = request.args.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing required query parameter: {name}")
    return value


def _verify_signature(incident_id: str, service_account_email: str, issued_at: str, signature: str) -> None:
    signing_secret = os.getenv("APPROVAL_SIGNING_SECRET")
    if not signing_secret:
        raise ValueError("Missing APPROVAL_SIGNING_SECRET environment variable")

    max_age_seconds = int(os.getenv("APPROVAL_MAX_AGE_SECONDS", "3600"))
    now = int(time.time())
    issued_ts = int(issued_at)
    if issued_ts > now + 300:
        raise PermissionError("Approval link issue time is invalid")
    if now - issued_ts > max_age_seconds:
        raise PermissionError("Approval link has expired")

    payload = f"{incident_id}|{service_account_email}|{issued_at}"
    expected_sig = hmac.new(
        signing_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        raise PermissionError("Invalid signature")


def _disable_service_account(project_id: str, service_account_email: str) -> Dict:
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    authed_session = AuthorizedSession(credentials)

    encoded_sa = quote(service_account_email, safe="")
    url = f"{IAM_API_BASE}/projects/{project_id}/serviceAccounts/{encoded_sa}"
    response = authed_session.patch(
        url,
        params={"updateMask": "disabled"},
        json={"disabled": True},
        timeout=30,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"IAM disable failed ({response.status_code}): {response.text[:500]}"
        )

    return response.json()


def _resolve_scc_parent() -> str:
    source_name = os.getenv("SCC_SOURCE_NAME", "").strip()
    if source_name:
        return source_name

    org_id = os.getenv("SCC_ORGANIZATION_ID", "").strip()
    source_id = os.getenv("SCC_SOURCE_ID", "").strip()
    if not org_id or not source_id:
        raise ValueError(
            "Missing SCC source config: provide SCC_SOURCE_NAME or both SCC_ORGANIZATION_ID + SCC_SOURCE_ID"
        )

    return f"organizations/{org_id}/sources/{source_id}"


def _write_scc_finding(
    incident_id: str,
    service_account_email: str,
    project_id: str,
    remediation_result: Dict,
) -> str:
    client = securitycenter_v1.SecurityCenterClient()
    parent = _resolve_scc_parent()

    event_time = datetime.now(timezone.utc)
    finding = securitycenter_v1.Finding(
        state=securitycenter_v1.Finding.State.ACTIVE,
        category="SOC_AUTO_REMEDIATION",
        resource_name=f"//cloudresourcemanager.googleapis.com/projects/{project_id}",
        event_time=event_time,
        source_properties={
            "incident_id": incident_id,
            "service_account_email": service_account_email,
            "action": "disable_service_account",
            "status": "completed",
            "remediation_result": str(remediation_result),
        },
    )

    finding_id = uuid.uuid4().hex[:32]
    created = client.create_finding(
        request={"parent": parent, "finding_id": finding_id, "finding": finding}
    )
    return created.name


def main(request):
    """HTTP webhook entrypoint: approve -> disable IAM -> push SCC finding."""
    try:
        action = _require_query_arg(request, "action")
        if action != "approve":
            return ({"status": "ignored", "reason": "unsupported action"}, 400)

        incident_id = _require_query_arg(request, "incident_id")
        service_account_email = _require_query_arg(request, "service_account_email")
        issued_at = _require_query_arg(request, "issued_at")
        signature = _require_query_arg(request, "sig")

        _verify_signature(incident_id, service_account_email, issued_at, signature)

        project_id = os.getenv("PROJECT_ID", "").strip()
        if not project_id:
            raise ValueError("Missing PROJECT_ID environment variable")

        remediation_result = _disable_service_account(project_id, service_account_email)
        finding_name = _write_scc_finding(
            incident_id=incident_id,
            service_account_email=service_account_email,
            project_id=project_id,
            remediation_result=remediation_result,
        )

        logger.info(
            "Approved incident_id=%s service_account=%s finding=%s",
            incident_id,
            service_account_email,
            finding_name,
        )

        return (
            {
                "status": "ok",
                "incident_id": incident_id,
                "service_account_email": service_account_email,
                "finding": finding_name,
            },
            200,
        )
    except ValueError as exc:
        logger.warning("Invalid webhook request: %s", exc)
        return ({"status": "error", "message": str(exc)}, 400)
    except PermissionError as exc:
        logger.warning("Permission validation failed: %s", exc)
        return ({"status": "error", "message": str(exc)}, 403)
    except Exception as exc:
        logger.exception("Webhook remediation failed: %s", exc)
        return ({"status": "error", "message": str(exc)}, 500)
