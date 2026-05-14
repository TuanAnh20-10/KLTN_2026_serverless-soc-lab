import hashlib
import hmac
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict
from urllib.parse import quote

import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.cloud import securitycenter_v2
from google.protobuf import timestamp_pb2
from dotenv import load_dotenv


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

IAM_API_BASE = "https://iam.googleapis.com/v1"
VN_TZ = timezone(timedelta(hours=7))

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


def _verify_signature(incident_id: str, service_account_email: str, severity: str, pipeline: str, issued_at: str, signature: str) -> None:
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

    payload = f"{incident_id}|{service_account_email}|{severity}|{pipeline}|{issued_at}"
    expected_sig = hmac.new(
        signing_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        raise PermissionError("Invalid signature")


def _is_sa_already_disabled(project_id: str, service_account_email: str) -> bool:
    """Check if a service account is already disabled (used as one-time-use guard)."""
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    authed_session = AuthorizedSession(credentials)

    encoded_sa = quote(service_account_email, safe="")
    url = f"{IAM_API_BASE}/projects/{project_id}/serviceAccounts/{encoded_sa}"
    response = authed_session.get(url, timeout=15)

    if response.status_code >= 400:
        logger.warning("SA status check failed (%d): %s", response.status_code, response.text[:200])
        return False

    return response.json().get("disabled", False)


def _disable_service_account(project_id: str, service_account_email: str) -> Dict:
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    authed_session = AuthorizedSession(credentials)

    encoded_sa = quote(service_account_email, safe="")
    url = f"{IAM_API_BASE}/projects/{project_id}/serviceAccounts/{encoded_sa}:disable"
    response = authed_session.post(
        url,
        json={},
        timeout=30,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"IAM disable failed ({response.status_code}): {response.text[:500]}"
        )

    return response.json()


def _resolve_scc_parent() -> str:
    """Resolve the SCC source parent path.
    
    SCC V2 API requires the parent to include /locations/{location}.
    Format: organizations/{org_id}/sources/{source_id}/locations/global
    """
    source_name = os.getenv("SCC_SOURCE_NAME", "").strip()
    if not source_name:
        org_id = os.getenv("SCC_ORGANIZATION_ID", "").strip()
        source_id = os.getenv("SCC_SOURCE_ID", "").strip()
        if not org_id or not source_id:
            raise ValueError(
                "Missing SCC source config: provide SCC_SOURCE_NAME or both SCC_ORGANIZATION_ID + SCC_SOURCE_ID"
            )
        source_name = f"organizations/{org_id}/sources/{source_id}"

    # SCC V2 API requires /locations/{location} in the parent path
    if "/locations/" not in source_name:
        source_name = f"{source_name}/locations/global"

    return source_name


def _is_crown_jewel_incident(pipeline: str) -> bool:
    """Determine if this incident originates from the Crown Jewel real-time pipeline.

    Uses the explicit `pipeline` query parameter set by the originating bot,
    not AI severity output, to ensure deterministic classification.
    """
    return pipeline.lower() == "crown_jewel"


def _write_scc_finding(
    incident_id: str,
    service_account_email: str,
    project_id: str,
    remediation_result: Dict,
    severity: str = "HIGH",
    pipeline: str = "bulk_download",
) -> str:
    """Create a rich SCC V2 finding documenting the incident and remediation.

    Uses the explicit `pipeline` parameter (set by the originating bot)
    to determine context-appropriate content:
    - pipeline='crown_jewel'   → Crown Jewel real-time pipeline
    - pipeline='bulk_download' → Bulk download (mass exfiltration) pipeline
    """
    client = securitycenter_v2.SecurityCenterClient()
    parent = _resolve_scc_parent()

    project_num = os.getenv("PROJECT_NUMBER", project_id).strip()
    if not project_num:
        project_num = project_id

    now = datetime.now(timezone.utc)
    event_time = timestamp_pb2.Timestamp()
    event_time.FromDatetime(now)

    is_crown_jewel = _is_crown_jewel_incident(pipeline)

    # ── Build the enriched Finding ──────────────────────────────────────
    finding = securitycenter_v2.Finding()
    finding.state = securitycenter_v2.Finding.State.ACTIVE
    finding.finding_class = securitycenter_v2.Finding.FindingClass.THREAT
    # Map AI severity string to SCC severity enum
    severity_map = {
        "LOW": securitycenter_v2.Finding.Severity.LOW,
        "MEDIUM": securitycenter_v2.Finding.Severity.MEDIUM,
        "HIGH": securitycenter_v2.Finding.Severity.HIGH,
        "CRITICAL": securitycenter_v2.Finding.Severity.CRITICAL,
    }
    finding.severity = severity_map.get(
        severity.upper(), securitycenter_v2.Finding.Severity.HIGH
    )
    finding.resource_name = (
        f"//cloudresourcemanager.googleapis.com/projects/{project_num}"
    )
    finding.event_time = event_time

    if is_crown_jewel:
        # ── Crown Jewel Real-time Pipeline ──────────────────────────────
        finding.category = "CROWN_JEWEL_ACCESS_AUTO_REMEDIATED"

        finding.description = (
            f"[SOC Real-time Response] Crown Jewel access detected and remediated.\n\n"
            f"Incident ID: {incident_id}\n"
            f"Compromised Service Account: {service_account_email}\n"
            f"Project: {project_id} ({project_num})\n\n"
            f"A compromised service account key was used to access a top-priority "
            f"asset (Crown Jewel) in Cloud Storage. The real-time Log Sink pipeline "
            f"detected the access within seconds and triggered the Crown Jewel Bot, "
            f"which analyzed the event via AI and sent an immediate approval request "
            f"to the admin via Telegram. Upon admin approval, the SOAR webhook "
            f"automatically disabled the service account to prevent further access."
        )

        finding.next_steps = (
            "1. Immediately rotate all keys for the compromised service account.\n"
            "2. Assess which crown jewel files were accessed and their sensitivity.\n"
            "3. Determine if accessed data (keys, credentials, M&A docs) has been leaked.\n"
            "4. Activate incident response plan for crown jewel compromise.\n"
            "5. Review access policies and consider tightening IAM controls on crown jewel buckets.\n"
            "6. Re-enable the service account only after full forensic investigation."
        )

        # MITRE ATT&CK: Collection + Exfiltration of sensitive data
        finding.mitre_attack = securitycenter_v2.MitreAttack(
            primary_tactic=securitycenter_v2.MitreAttack.Tactic.COLLECTION,
            primary_techniques=[
                securitycenter_v2.MitreAttack.Technique.AUTOMATED_COLLECTION,
            ],
            additional_tactics=[
                securitycenter_v2.MitreAttack.Tactic.CREDENTIAL_ACCESS,
                securitycenter_v2.MitreAttack.Tactic.EXFILTRATION,
            ],
            additional_techniques=[
                securitycenter_v2.MitreAttack.Technique.STEAL_APPLICATION_ACCESS_TOKEN,
                securitycenter_v2.MitreAttack.Technique.VALID_ACCOUNTS,
            ],
        )

        # Exfiltration source: Crown Jewel bucket
        crown_jewel_bucket = os.getenv(
            "CROWN_JEWEL_BUCKET",
            "secops-lab-crown-jewels",
        )
        finding.exfiltration = securitycenter_v2.Exfiltration(
            sources=[
                securitycenter_v2.ExfilResource(
                    name=f"//storage.googleapis.com/projects/_/buckets/{crown_jewel_bucket}",
                    components=["STORAGE_OBJECTS"],
                )
            ],
        )

        pipeline_type = "CROWN_JEWEL_REALTIME"
    else:
        # ── Bulk Download (Mass Exfiltration) Pipeline ──────────────────
        finding.category = "DATA_EXFILTRATION_AUTO_REMEDIATED"

        finding.description = (
            f"[SOC Automated Response] Mass data exfiltration detected and remediated.\n\n"
            f"Incident ID: {incident_id}\n"
            f"Compromised Service Account: {service_account_email}\n"
            f"Project: {project_id} ({project_num})\n\n"
            f"A compromised service account key was used to download a large number of "
            f"files from Cloud Storage in a short period, triggering an alert policy. "
            f"The SOC orchestrator analyzed the activity via Gemini AI and sent an "
            f"approval request to the admin via Telegram. Upon admin approval, the "
            f"SOAR webhook automatically disabled the service account to stop the "
            f"data exfiltration."
        )

        finding.next_steps = (
            "1. Rotate all keys for the compromised service account.\n"
            "2. Review Cloud Audit Logs to identify all accessed objects.\n"
            "3. Assess the sensitivity of exfiltrated data.\n"
            "4. Check if the compromised key was exposed in any repository or log.\n"
            "5. Re-enable the service account only after the investigation is complete."
        )

        # MITRE ATT&CK: Automated exfiltration
        finding.mitre_attack = securitycenter_v2.MitreAttack(
            primary_tactic=securitycenter_v2.MitreAttack.Tactic.EXFILTRATION,
            primary_techniques=[
                securitycenter_v2.MitreAttack.Technique.AUTOMATED_EXFILTRATION,
            ],
            additional_tactics=[
                securitycenter_v2.MitreAttack.Tactic.CREDENTIAL_ACCESS,
            ],
            additional_techniques=[
                securitycenter_v2.MitreAttack.Technique.STEAL_APPLICATION_ACCESS_TOKEN,
                securitycenter_v2.MitreAttack.Technique.VALID_ACCOUNTS,
            ],
        )

        # Exfiltration source: Honeypot bucket
        finding.exfiltration = securitycenter_v2.Exfiltration(
            sources=[
                securitycenter_v2.ExfilResource(
                    name=f"//storage.googleapis.com/projects/_/buckets/{os.getenv('HONEYPOT_BUCKET', 'secops-lab-confidential-data')}",
                    components=["STORAGE_OBJECTS"],
                )
            ],
        )

        pipeline_type = "BULK_DOWNLOAD_MONITORING"

    # ── Access Info (compromised identity) — shared by both pipelines ───
    finding.access = securitycenter_v2.Access(
        principal_email=service_account_email,
        service_name="storage.googleapis.com",
        method_name="google.storage.objects.get",
        principal_subject=f"serviceAccount:{service_account_email}",
    )

    # ── Source Properties (custom metadata) ─────────────────────────────
    finding.source_properties = {
        "incident_id": incident_id,
        "compromised_service_account": service_account_email,
        "remediation_action": "DISABLE_SERVICE_ACCOUNT",
        "remediation_status": "COMPLETED",
        "remediation_method": "SOAR_AUTOMATED_WEBHOOK",
        "approval_method": "HUMAN_IN_THE_LOOP_TELEGRAM",
        "pipeline_type": pipeline_type,
        "project_id": project_id,
    }

    finding_id = f"f{uuid.uuid4().hex[:31]}"

    logger.info(
        "SCC create_finding request: parent=%s, finding_id=%s, category=%s, pipeline=%s",
        parent, finding_id, finding.category, pipeline_type,
    )

    request = securitycenter_v2.CreateFindingRequest(
        parent=parent,
        finding_id=finding_id,
        finding=finding,
    )

    try:
        created = client.create_finding(request=request)
        logger.info("SCC finding created successfully: %s", created.name)
        return created.name
    except Exception as scc_exc:
        logger.warning(
            "SCC create_finding failed (non-blocking): %s. "
            "Finding logged to Cloud Logging instead.",
            scc_exc,
        )
        return None


def _log_remediation_record(
    incident_id: str,
    service_account_email: str,
    project_id: str,
    remediation_result: Dict,
    finding_name: str,
) -> None:
    """Write a structured remediation record to Cloud Logging as a reliable audit trail."""
    logger.info(
        "REMEDIATION_RECORD: incident_id=%s service_account=%s project=%s "
        "action=disable_service_account status=completed scc_finding=%s "
        "remediation_result=%s",
        incident_id,
        service_account_email,
        project_id,
        finding_name or "SCC_WRITE_FAILED",
        str(remediation_result),
    )


def _build_html_response(
    incident_id: str,
    service_account_email: str,
    sa_disabled: bool,
    finding_name: str,
) -> str:
    """Build a clear HTML response page showing the remediation results."""
    scc_status = "✅ Created" if finding_name else "⚠️ Failed (logged to Cloud Logging)"
    scc_detail = finding_name if finding_name else "SCC write error — audit trail saved to Cloud Logging"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOC Remediation Result</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px;
    }}
    .card {{
      background: rgba(30, 41, 59, 0.8);
      border: 1px solid rgba(99, 102, 241, 0.3);
      border-radius: 16px; padding: 40px;
      max-width: 680px; width: 100%;
      box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    }}
    .header {{
      display: flex; align-items: center; gap: 14px;
      margin-bottom: 28px; padding-bottom: 20px;
      border-bottom: 1px solid rgba(99, 102, 241, 0.2);
    }}
    .header .icon {{ font-size: 36px; }}
    .header h1 {{
      font-size: 22px; font-weight: 700;
      background: linear-gradient(135deg, #818cf8, #c084fc);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }}
    .header .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 2px; }}
    .step {{
      display: flex; align-items: flex-start; gap: 14px;
      padding: 16px 18px; border-radius: 12px;
      margin-bottom: 12px; transition: background 0.2s;
    }}
    .step:hover {{ background: rgba(99, 102, 241, 0.08); }}
    .step .emoji {{ font-size: 24px; flex-shrink: 0; margin-top: 2px; }}
    .step .info {{ flex: 1; }}
    .step .label {{
      font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
      color: #64748b; margin-bottom: 4px;
    }}
    .step .value {{ font-size: 15px; font-weight: 600; }}
    .step .detail {{
      font-size: 12px; color: #94a3b8; margin-top: 4px;
      word-break: break-all;
    }}
    .success {{ color: #34d399; }}
    .warning {{ color: #fbbf24; }}
    .meta {{
      margin-top: 24px; padding-top: 18px;
      border-top: 1px solid rgba(99, 102, 241, 0.15);
      display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
    }}
    .meta-item .label {{ font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
    .meta-item .value {{ font-size: 13px; color: #cbd5e1; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <span class="icon">🛡️</span>
      <div>
        <h1>SOC Automated Remediation</h1>
        <div class="subtitle">Incident response completed</div>
      </div>
    </div>

    <div class="step">
      <span class="emoji">{"✅" if sa_disabled else "❌"}</span>
      <div class="info">
        <div class="label">Step 1 — Disable Compromised Service Account</div>
        <div class="value {"success" if sa_disabled else ""}">
          {"Service account disabled successfully" if sa_disabled else "Failed to disable service account"}
        </div>
        <div class="detail">{service_account_email}</div>
      </div>
    </div>

    <div class="step">
      <span class="emoji">{"✅" if finding_name else "⚠️"}</span>
      <div class="info">
        <div class="label">Step 2 — Write SCC Finding</div>
        <div class="value {"success" if finding_name else "warning"}">{scc_status}</div>
        <div class="detail">{scc_detail}</div>
      </div>
    </div>

    <div class="meta">
      <div class="meta-item">
        <div class="label">Incident ID</div>
        <div class="value">{incident_id}</div>
      </div>
      <div class="meta-item">
        <div class="label">Timestamp (UTC+7)</div>
        <div class="value">{datetime.now(VN_TZ).strftime("%Y-%m-%d %H:%M:%S")}</div>
      </div>
    </div>
  </div>
</body>
</html>"""


def _build_already_used_html(incident_id: str, service_account_email: str) -> str:
    """Build an HTML page indicating the approval link was already used."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link Already Used</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px;
    }}
    .card {{
      background: rgba(30, 41, 59, 0.8);
      border: 1px solid rgba(251, 191, 36, 0.4);
      border-radius: 16px; padding: 40px;
      max-width: 580px; width: 100%; text-align: center;
      box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 22px; color: #fbbf24; margin-bottom: 8px; }}
    .msg {{ font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 20px; }}
    .detail {{ font-size: 12px; color: #64748b; word-break: break-all; }}
    .detail span {{ color: #94a3b8; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Approval Link Already Used</h1>
    <div class="msg">
      This remediation has already been executed.<br>
      The service account was disabled by a previous approval.
    </div>
    <div class="detail">
      Incident: <span>{incident_id}</span><br>
      Service Account: <span>{service_account_email}</span><br>
      Time: <span>{datetime.now(VN_TZ).strftime("%Y-%m-%d %H:%M:%S")} (UTC+7)</span>
    </div>
  </div>
</body>
</html>"""


def _build_expired_html(message: str) -> str:
    """Build an HTML page for expired or invalid approval links."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link Expired</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px;
    }}
    .card {{
      background: rgba(30, 41, 59, 0.8);
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 16px; padding: 40px;
      max-width: 480px; width: 100%; text-align: center;
      box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 22px; color: #ef4444; margin-bottom: 8px; }}
    .msg {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>Link Expired or Invalid</h1>
    <div class="msg">{message}</div>
  </div>
</body>
</html>"""


def main(request):
    """HTTP webhook entrypoint: approve -> disable IAM -> push SCC finding."""
    try:
        action = _require_query_arg(request, "action")
        if action != "approve":
            return ({"status": "ignored", "reason": "unsupported action"}, 400)

        incident_id = _require_query_arg(request, "incident_id")
        service_account_email = _require_query_arg(request, "service_account_email")
        severity = request.args.get("severity", "HIGH").strip().upper()
        pipeline = request.args.get("pipeline", "bulk_download").strip().lower()
        issued_at = _require_query_arg(request, "issued_at")
        signature = _require_query_arg(request, "sig")

        _verify_signature(incident_id, service_account_email, severity, pipeline, issued_at, signature)

        project_id = os.getenv("PROJECT_ID", "").strip()
        if not project_id:
            raise ValueError("Missing PROJECT_ID environment variable")

        # ── One-time-use guard ──────────────────────────────────────────
        # If the SA is already disabled, this link was already used.
        if _is_sa_already_disabled(project_id, service_account_email):
            logger.info(
                "Duplicate approval blocked: incident_id=%s sa=%s (already disabled)",
                incident_id, service_account_email,
            )
            html = _build_already_used_html(incident_id, service_account_email)
            return (html, 200, {"Content-Type": "text/html; charset=utf-8"})

        # Step 1: Disable the compromised service account (critical)
        remediation_result = _disable_service_account(project_id, service_account_email)

        # Step 2: Write SCC finding (best-effort, non-blocking)
        finding_name = _write_scc_finding(
            incident_id=incident_id,
            service_account_email=service_account_email,
            project_id=project_id,
            remediation_result=remediation_result,
            severity=severity,
            pipeline=pipeline,
        )

        # Step 3: Always log the remediation record to Cloud Logging
        _log_remediation_record(
            incident_id=incident_id,
            service_account_email=service_account_email,
            project_id=project_id,
            remediation_result=remediation_result,
            finding_name=finding_name,
        )

        logger.info(
            "Remediation complete: incident_id=%s sa=%s sa_disabled=True scc_finding=%s",
            incident_id,
            service_account_email,
            finding_name or "FAILED",
        )

        # Return a rich HTML page showing results
        html = _build_html_response(
            incident_id=incident_id,
            service_account_email=service_account_email,
            sa_disabled=True,
            finding_name=finding_name,
        )
        return (html, 200, {"Content-Type": "text/html; charset=utf-8"})

    except ValueError as exc:
        logger.warning("Invalid webhook request: %s", exc)
        return ({"status": "error", "message": str(exc)}, 400)
    except PermissionError as exc:
        logger.warning("Permission validation failed: %s", exc)
        html = _build_expired_html(str(exc))
        return (html, 403, {"Content-Type": "text/html; charset=utf-8"})
    except Exception as exc:
        logger.exception("Webhook remediation failed: %s", exc)
        return ({"status": "error", "message": str(exc)}, 500)

