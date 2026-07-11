"""
Orchestrator Bot — NO ENRICHMENT VERSION
=========================================
Phiên bản so sánh: BỎ toàn bộ 4 lớp Context Enrichment.
AI chỉ nhận raw alert data từ Cloud Monitoring (không có IP, User Agent, Time-of-Day).
Mục đích: Chứng minh Context Enrichment cải thiện chất lượng phân tích AI.

So sánh với orchestrator_bot/main.py (bản đầy đủ):
  - Không có Layer 1: Cloud Logging Query (callerIp, userAgent)
  - Không có Layer 2: IP Geolocation (ip-api.com)
  - Không có Layer 3: User Agent Analysis
  - Không có Layer 4: Time-of-Day Context
  - Prompt AI đơn giản, không hướng dẫn risk factors
  - Không có HMAC signing, không có Approve button (chỉ gửi thông báo)
"""

import ast
import base64
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

GEMINI_API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
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


# ═══════════════════════════════════════════════════════════════
# Pub/Sub payload extraction (giống bản gốc)
# ═══════════════════════════════════════════════════════════════

def _coerce_payload_object(decoded_text: str) -> Dict[str, Any]:
    candidate = decoded_text.strip()
    if not candidate:
        raise ValueError("Decoded Pub/Sub message is empty")
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        parsed = ast.literal_eval(candidate)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    if not isinstance(parsed, dict):
        raise ValueError("Decoded Pub/Sub message must be a JSON object")
    return parsed


def _extract_pubsub_payload(event: Any) -> Dict[str, Any]:
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
        raise ValueError("AI structured output is not a JSON object")
    return parsed


# ═══════════════════════════════════════════════════════════════
# KHÔNG CÓ ENRICHMENT — Chỉ trích xuất raw data từ payload
# ═══════════════════════════════════════════════════════════════

def _normalize_for_triage_no_enrichment(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ONLY raw alert data — NO enrichment layers.

    Differences vs full version:
      ❌ Layer 1: No Cloud Logging query (no callerIp, no userAgent)
      ❌ Layer 2: No IP geolocation (no country, city, ISP)
      ❌ Layer 3: No User Agent analysis
      ❌ Layer 4: No Time-of-Day context
    """
    principal = _deep_find_first(
        payload,
        {"principalEmail", "principal_email", "actor", "caller"},
    )
    service_account = _deep_find_first(
        payload,
        {"serviceAccountEmail", "service_account_email", "targetServiceAccount", "member"},
    )
    method_name = _deep_find_first(payload, {"methodName", "method_name", "action"})
    resource_name = _deep_find_first(payload, {"resourceName", "resource_name", "resource"})
    event_time = _deep_find_first(payload, {"timestamp", "eventTime", "time"})

    logger.info("[NO-ENRICHMENT] Skipping ALL 4 enrichment layers")
    logger.info("[NO-ENRICHMENT] Raw data only: principal=%s, action=%s", principal, method_name)

    return {
        "principal_email": principal or "unknown",
        "service_account_email": _normalize_service_account_email(service_account) or "unknown",
        "action": method_name or "unknown",
        "resource_name": resource_name or "unknown",
        "event_time": event_time or "unknown",
        "raw_event": payload,
    }


# ═══════════════════════════════════════════════════════════════
# PROMPT ĐƠN GIẢN — Không hướng dẫn risk factors
# ═══════════════════════════════════════════════════════════════

def _build_triage_prompt_no_enrichment(triage_input: Dict[str, Any]) -> str:
    """Build a BASIC prompt without enrichment context guidance.

    Differences vs full version:
      ❌ No mention of enrichment fields (IP, User Agent, Time-of-Day)
      ❌ No risk factor guidance (foreign IP, automated tools, off-hours)
      ❌ No organization context (Vietnam-based)
    """
    return (
        "You are a SOC analyst. "
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
        "Do not include markdown, comments, or extra keys. "
        f"Event: {json.dumps(triage_input, ensure_ascii=True)}"
    )


# ═══════════════════════════════════════════════════════════════
# AI Triage — Chỉ dùng Gemini (không cần fallback cho demo)
# ═══════════════════════════════════════════════════════════════

def _call_gemini(triage_input: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Missing GEMINI_API_KEY environment variable")

    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    prompt = _build_triage_prompt_no_enrichment(triage_input)

    url = GEMINI_API_URL_TEMPLATE.format(model=model)
    request_body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    response = requests.post(
        f"{url}?key={api_key}",
        json=request_body,
        timeout=60,
    )
    response.raise_for_status()

    data = response.json()
    text_output = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    if not text_output:
        raise ValueError("Gemini response text is empty")

    structured = _parse_structured_json(text_output)

    # Validate required fields
    required = {"severity", "confidence", "should_escalate", "summary", "reason"}
    missing = [k for k in required if k not in structured]
    if missing:
        raise ValueError(f"AI output missing fields: {missing}")

    return structured


# ═══════════════════════════════════════════════════════════════
# Telegram — Gửi tin nhắn (KHÔNG có nút Approve)
# ═══════════════════════════════════════════════════════════════

def _send_telegram_alert_no_enrichment(incident_id: str, triage: Dict[str, Any]) -> None:
    """Send alert to a SEPARATE Telegram bot (no approval button)."""
    bot_token = os.getenv("TELE_BOT_TOKEN_NO_ENRICHMENT")
    chat_id = os.getenv("TELE_CHAT_ID_NO_ENRICHMENT")
    if not bot_token:
        raise ValueError("Missing TELE_BOT_TOKEN_NO_ENRICHMENT")
    if not chat_id:
        raise ValueError("Missing TELE_CHAT_ID_NO_ENRICHMENT")

    message_text = (
        "⚠️ [NO-ENRICHMENT] SOC Alert\n"
        f"Incident ID: {incident_id}\n"
        f"Severity: {triage.get('severity')}\n"
        f"Confidence: {triage.get('confidence')}\n"
        f"Escalate: {triage.get('should_escalate')}\n"
        f"Service Account: {triage.get('service_account_email', 'unknown')}\n"
        f"Summary: {triage.get('summary')}\n"
        f"Reason: {triage.get('reason')}\n"
        f"Remediation: {triage.get('recommended_remediation', 'N/A')}"
    )

    url = TELEGRAM_API_URL_TEMPLATE.format(token=bot_token)
    response = requests.post(
        url,
        json={"chat_id": chat_id, "text": message_text},
        timeout=15,
    )
    response.raise_for_status()


# ═══════════════════════════════════════════════════════════════
# MAIN — Cloud Function entrypoint
# ═══════════════════════════════════════════════════════════════

def main(event: Any, context: Any = None) -> None:
    """Cloud Function entrypoint: Pub/Sub -> AI triage (NO enrichment) -> Telegram alert."""
    try:
        logger.info("[Step 1/4] Received Pub/Sub event — decoding payload...")
        payload = _extract_pubsub_payload(event)

        # ── Filter closed incidents ─────────────────────────────
        incident = payload.get("incident", {})
        incident_state = incident.get("state", "").lower()
        if incident_state == "closed":
            logger.info("[Step 1/4] Skipping CLOSED incident")
            return
        logger.info("[Step 1/4] Incident OPEN — proceeding WITHOUT enrichment")

        # ── Raw data only (NO enrichment) ───────────────────────
        logger.info("[Step 2/4] Extracting raw data (NO enrichment layers)...")
        triage_input = _normalize_for_triage_no_enrichment(payload)

        # ── AI Triage ───────────────────────────────────────────
        logger.info("[Step 3/4] Starting AI triage (Gemini, NO enrichment context)...")
        model_output = _call_gemini(triage_input)
        logger.info(
            "[Step 3/4] AI Result: severity=%s, confidence=%s, escalate=%s",
            model_output.get("severity"),
            model_output.get("confidence"),
            model_output.get("should_escalate"),
        )

        # ── Telegram alert (no approval button) ─────────────────
        incident_id = uuid.uuid4().hex[:16]
        logger.info("[Step 4/4] Sending Telegram alert (NO-ENRICHMENT bot)...")
        _send_telegram_alert_no_enrichment(incident_id, model_output)

        logger.info(
            "[DONE] NO-ENRICHMENT pipeline complete: severity=%s, confidence=%s",
            model_output.get("severity"),
            model_output.get("confidence"),
        )
    except Exception as exc:
        logger.exception("[ERROR] Failed: %s", exc)
        raise
