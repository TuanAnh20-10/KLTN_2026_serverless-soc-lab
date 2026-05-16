import ast
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import requests
from requests.exceptions import ReadTimeout
from dotenv import load_dotenv
import google.auth
import google.auth.transport.requests as google_requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

GEMINI_API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_FALLBACK_MODEL = "gpt-5.4-mini"
TELEGRAM_API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

load_dotenv()


def _load_repo_env() -> None:
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        env_path = parent / ".env"
        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=False)
            break


_load_repo_env()


def _coerce_payload_object(decoded_text: str) -> Dict[str, Any]:
    candidate = decoded_text.strip()
    if not candidate:
        raise ValueError("Decoded Pub/Sub message is empty")

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        # Some ad-hoc test publishers send Python-dict strings with single quotes.
        parsed = ast.literal_eval(candidate)

    if isinstance(parsed, str):
        parsed = json.loads(parsed)

    if not isinstance(parsed, dict):
        raise ValueError("Decoded Pub/Sub message must be a JSON object")

    return parsed


def _extract_pubsub_payload(event: Any) -> Dict[str, Any]:
    """Extract and decode Pub/Sub payload from either CloudEvent or background event."""
    event_data = event.data if hasattr(event, "data") else event
    if not isinstance(event_data, dict):
        raise ValueError("Pub/Sub event data must be a dictionary")

    message = event_data.get("message")
    if isinstance(message, dict):
        raw_data = message.get("data")
    else:
        raw_data = event_data.get("data")

    if not raw_data:
        raise ValueError("Missing Pub/Sub message data")

    if isinstance(raw_data, bytes):
        decoded_text = raw_data.decode("utf-8")
        return _coerce_payload_object(decoded_text)

    decoded_bytes = base64.b64decode(raw_data)
    decoded_text = decoded_bytes.decode("utf-8")
    return _coerce_payload_object(decoded_text)


def _deep_find_first(obj: Any, keys: set[str]) -> Optional[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in keys and isinstance(value, str) and value.strip():
                return value.strip()
            found = _deep_find_first(value, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _deep_find_first(item, keys)
            if found:
                return found
    return None


def _normalize_service_account_email(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    email = value.strip()
    if email.startswith("serviceAccount:"):
        email = email.split(":", 1)[1].strip()

    return email or None


def _parse_structured_json(text_output: str) -> Dict[str, Any]:
    candidate = text_output.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if candidate.startswith("json"):
            candidate = candidate[4:].strip()

    parsed = json.loads(candidate)
    if not isinstance(parsed, dict):
        raise ValueError("Gemini structured output is not a JSON object")
    return parsed


def _geolocate_ip(ip_str: Optional[str]) -> Dict[str, str]:
    """Resolve an IP address to geographic context via ip-api.com.

    Returns country, city, ISP for the AI to detect
    geographic anomalies (e.g., access from unexpected country).
    Free tier: 45 requests/minute — sufficient for alert-driven pipeline.
    This is context enrichment only, NOT used for allow/deny decisions.
    """
    fallback = {"country": "unknown", "city": "unknown", "isp": "unknown"}
    if not ip_str or ip_str == "unknown":
        return fallback
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,city,isp,org",
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "unknown"),
                    "city": data.get("city", "unknown"),
                    "isp": data.get("isp", "unknown"),
                }
        return fallback
    except Exception:
        logger.warning("IP geolocation lookup failed for %s — using fallback", ip_str)
        return fallback


def _fetch_caller_ip_from_logs(principal_email: str) -> Optional[str]:
    """Query Cloud Logging API to retrieve the callerIp from recent audit logs.

    The Cloud Monitoring Alert notification does NOT contain callerIp—it only
    includes aggregated metric data.  To get the actual IP, we query the
    audit log entries that triggered the alert.
    """
    project_id = os.getenv("PROJECT_ID", "")
    if not project_id or not principal_email or principal_email == "unknown":
        return None

    try:
        credentials, _ = google.auth.default()
        credentials.refresh(google.auth.transport.requests.Request())
        auth_session = google.auth.transport.requests.AuthorizedSession(credentials)

        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        log_filter = (
            f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" '
            f'AND protoPayload.methodName="storage.objects.get" '
            f'AND protoPayload.authenticationInfo.principalEmail="{principal_email}" '
            f'AND timestamp>="{since}"'
        )
        body = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": 1,
        }
        resp = auth_session.post(
            "https://logging.googleapis.com/v2/entries:list",
            json=body,
            timeout=10,
        )
        if resp.status_code == 200:
            entries = resp.json().get("entries", [])
            if entries:
                caller_ip = (
                    entries[0]
                    .get("protoPayload", {})
                    .get("requestMetadata", {})
                    .get("callerIp")
                )
                if caller_ip:
                    logger.info("Fetched callerIp from Cloud Logging: %s", caller_ip)
                    return caller_ip
        return None
    except Exception as exc:
        logger.warning("Cloud Logging query for callerIp failed: %s", exc)
        return None


def _normalize_for_triage(payload: Dict[str, Any]) -> Dict[str, Any]:
    principal = _deep_find_first(
        payload,
        {
            "principalEmail",
            "principal_email",
            "actor",
            "caller",
            "authenticationInfo.principalEmail",
        },
    )
    service_account = _deep_find_first(
        payload,
        {
            "serviceAccountEmail",
            "service_account_email",
            "targetServiceAccount",
            "member",
        },
    )
    method_name = _deep_find_first(payload, {"methodName", "method_name", "action"})
    resource_name = _deep_find_first(payload, {"resourceName", "resource_name", "resource"})
    event_time = _deep_find_first(payload, {"timestamp", "eventTime", "time"})

    # callerIp: try payload first, then query Cloud Logging as fallback
    caller_ip = _deep_find_first(payload, {"callerIp", "caller_ip", "sourceIp", "remoteIp"})
    if not caller_ip:
        caller_ip = _fetch_caller_ip_from_logs(
            principal or _normalize_service_account_email(service_account) or "unknown"
        )

    ip_geo = _geolocate_ip(caller_ip)

    return {
        "principal_email": principal or "unknown",
        "service_account_email": _normalize_service_account_email(service_account) or "unknown",
        "action": method_name or "unknown",
        "resource_name": resource_name or "unknown",
        "event_time": event_time or "unknown",
        "caller_ip": caller_ip or "unknown",
        "ip_country": ip_geo["country"],
        "ip_city": ip_geo["city"],
        "ip_isp": ip_geo["isp"],
        "raw_event": payload,
    }

def _build_triage_prompt(triage_input: Dict[str, Any]) -> str:
    """Build the SOC triage prompt (shared by all AI providers)."""
    return (
        "You are a SOC triage assistant for a GCP security pipeline "
        "that monitors a honeypot bucket to detect insider threats. "
        "This organization is based in Vietnam. "
        "Analyze this GCP audit event and return ONLY valid JSON "
        "with this exact schema: "
        "{"
        '"severity":"LOW|MEDIUM|HIGH|CRITICAL",'
        '"confidence":0.0,'
        '"should_escalate":true,'
        '"summary":"...",'
        '"reason":"...",'
        '"recommended_remediation":"...",'
        '"service_account_email":"..."'
        "}. "
        "The event includes IP geolocation fields (ip_country, ip_city, ip_isp). "
        "Access from a foreign country is a strong indicator of credential theft, "
        "as stolen keys are often used from outside the organization's geography. "
        "Factor the caller IP geolocation into your overall assessment. "
        "Always mention the caller IP, country, and ISP in your reason. "
        "Do not include markdown, comments, or extra keys. "
        f"Event: {json.dumps(triage_input, ensure_ascii=True)}"
    )


def _validate_triage_output(structured: Dict[str, Any], triage_input: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize the structured triage output from any AI provider."""
    required = {
        "severity", "confidence", "should_escalate",
        "summary", "reason", "recommended_remediation",
        "service_account_email",
    }
    missing = [key for key in required if key not in structured]
    if missing:
        raise ValueError(f"AI structured output missing fields: {missing}")

    structured["service_account_email"] = (
        _normalize_service_account_email(structured.get("service_account_email"))
        or triage_input.get("service_account_email", "unknown")
    )
    return structured


def _call_gemini_structured(triage_input: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Missing GEMINI_API_KEY environment variable")

    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    prompt = _build_triage_prompt(triage_input)

    url = GEMINI_API_URL_TEMPLATE.format(model=model)
    request_body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    # Retry once on timeout — gemini-2.5-flash (thinking model) can be slow
    max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(
                url,
                params={"key": api_key},
                json=request_body,
                timeout=30,
            )
            response.raise_for_status()
            break
        except ReadTimeout:
            if attempt < max_attempts:
                logger.warning("Gemini API timeout (attempt %d/%d), retrying...", attempt, max_attempts)
            else:
                logger.error("Gemini API timeout after %d attempts", max_attempts)
                raise
    model_response = response.json()

    parts = (
        model_response.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [])
    )
    if not parts:
        raise ValueError("Gemini response has no content parts")

    text_output = parts[0].get("text", "").strip()
    if not text_output:
        raise ValueError("Gemini response text is empty")

    structured = _parse_structured_json(text_output)
    return _validate_triage_output(structured, triage_input)


def _call_openai_fallback(triage_input: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback AI provider: GPT-5.4 Mini via OpenAI API."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("Missing OPENAI_API_KEY environment variable (fallback unavailable)")

    prompt = _build_triage_prompt(triage_input)

    response = requests.post(
        OPENAI_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": OPENAI_FALLBACK_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        },
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    text_output = data["choices"][0]["message"]["content"].strip()
    if not text_output:
        raise ValueError("OpenAI response text is empty")

    structured = _parse_structured_json(text_output)
    return _validate_triage_output(structured, triage_input)


def _build_signed_approve_url(incident_id: str, service_account_email: str, severity: str) -> str:
    webhook_base_url = os.getenv("WEBHOOK_BASE_URL")
    signing_secret = os.getenv("APPROVAL_SIGNING_SECRET")
    if not webhook_base_url:
        raise ValueError("Missing WEBHOOK_BASE_URL environment variable")
    if not signing_secret:
        raise ValueError("Missing APPROVAL_SIGNING_SECRET environment variable")

    issued_at = str(int(time.time()))
    sign_payload = f"{incident_id}|{service_account_email}|{severity}|{issued_at}"
    signature = hmac.new(
        signing_secret.encode("utf-8"),
        sign_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    query = urlencode(
        {
            "action": "approve",
            "incident_id": incident_id,
            "service_account_email": service_account_email,
            "severity": severity,
            "issued_at": issued_at,
            "sig": signature,
        }
    )
    return f"{webhook_base_url}?{query}"


def _send_telegram_alert(incident_id: str, triage: Dict[str, Any], approve_url: str) -> None:
    bot_token = os.getenv("TELE_BOT_TOKEN")
    chat_id = os.getenv("TELE_CHAT_ID")
    if not bot_token:
        raise ValueError("Missing TELE_BOT_TOKEN environment variable")
    if not chat_id:
        raise ValueError("Missing TELE_CHAT_ID environment variable")

    message_text = (
        "[SOC Alert] Suspicious IAM Activity\n"
        f"Incident ID: {incident_id}\n"
        f"Severity: {triage.get('severity')}\n"
        f"Confidence: {triage.get('confidence')}\n"
        f"Escalate: {triage.get('should_escalate')}\n"
        f"Service Account: {triage.get('service_account_email')}\n"
        f"Summary: {triage.get('summary')}\n"
        f"Reason: {triage.get('reason')}\n"
        f"Remediation: {triage.get('recommended_remediation')}"
    )

    telegram_payload = {
        "chat_id": chat_id,
        "text": message_text,
        "reply_markup": {
            "inline_keyboard": [[{"text": "Approve Remediation", "url": approve_url}]]
        },
    }

    url = TELEGRAM_API_URL_TEMPLATE.format(token=bot_token)
    response = requests.post(url, json=telegram_payload, timeout=15)
    response.raise_for_status()


def main(event: Any, context: Any = None) -> None:
    """Cloud Function entrypoint: Pub/Sub -> AI triage (Gemini + OpenAI fallback) -> Telegram alert."""
    try:
        logger.info("[Step 1/6] Received Pub/Sub event — decoding Base64 payload...")
        payload = _extract_pubsub_payload(event)
        logger.info("[Step 1/6] Payload decoded successfully")

        # ── Filter out "closed" incident notifications ──────────────────
        incident = payload.get("incident", {})
        incident_state = incident.get("state", "").lower()
        policy_name = incident.get("policy_name", "unknown")

        logger.info("[Step 2/6] Checking incident state: state=%s, policy=%s", incident_state, policy_name)
        if incident_state == "closed":
            logger.info(
                "[Step 2/6] Skipping CLOSED incident (already remediated): policy=%s, ended_at=%s",
                policy_name,
                incident.get("ended_at", "unknown"),
            )
            return
        logger.info("[Step 2/6] Incident state is OPEN — proceeding with triage")

        logger.info("[Step 3/6] Normalizing event data for AI triage...")
        triage_input = _normalize_for_triage(payload)
        logger.info(
            "[Step 3/6] Normalized: principal=%s, sa=%s, caller_ip=%s (geo: %s, %s, ISP: %s)",
            triage_input.get("principal_email"),
            triage_input.get("service_account_email"),
            triage_input.get("caller_ip"),
            triage_input.get("ip_country"),
            triage_input.get("ip_city"),
            triage_input.get("ip_isp"),
        )

        # ── AI Triage with fallback ──────────────────────────────────
        logger.info("[Step 4/6] Starting AI triage — Primary: Gemini 2.5 Flash (timeout=30s)")
        ai_provider = "gemini"
        try:
            model_output = _call_gemini_structured(triage_input)
            logger.info("[Step 4/6] AI triage completed via Gemini")
        except Exception as gemini_exc:
            logger.warning(
                "[Step 4/6] Gemini failed (%s: %s) — switching to OpenAI GPT-5.4 Mini fallback...",
                type(gemini_exc).__name__, gemini_exc,
            )
            ai_provider = "openai-gpt-5.4-mini"
            model_output = _call_openai_fallback(triage_input)
            logger.info("[Step 4/6] AI triage completed via OpenAI fallback (GPT-5.4 Mini)")

        logger.info(
            "[Step 4/6] AI Result: severity=%s, confidence=%s, escalate=%s",
            model_output.get("severity"),
            model_output.get("confidence"),
            model_output.get("should_escalate"),
        )

        incident_id = uuid.uuid4().hex[:16]
        service_account_email = _normalize_service_account_email(
            model_output.get("service_account_email")
        ) or _normalize_service_account_email(
            triage_input.get("service_account_email")
        ) or "unknown"

        logger.info("[Step 5/6] Signing approval URL (HMAC-SHA256) — incident_id=%s", incident_id)
        approve_url = _build_signed_approve_url(
            incident_id=incident_id,
            service_account_email=service_account_email,
            severity=model_output.get("severity", "HIGH"),
        )

        logger.info("[Step 6/6] Sending Telegram alert to SOC Admin...")
        _send_telegram_alert(incident_id=incident_id, triage=model_output, approve_url=approve_url)

        logger.info(
            "[DONE] Pipeline complete: incident_id=%s | severity=%s | escalate=%s | ai_provider=%s | sa=%s",
            incident_id,
            model_output.get("severity"),
            model_output.get("should_escalate"),
            ai_provider,
            service_account_email,
        )
    except Exception as exc:
        logger.exception("[ERROR] Failed to process Pub/Sub event: %s", exc)
        raise
