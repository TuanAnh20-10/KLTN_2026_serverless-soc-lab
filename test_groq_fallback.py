"""
Test script: AI Model Comparison for SOC Triage
=================================================
Tests models across Gemini, Groq, NVIDIA NIM, and OpenAI APIs
with a realistic Cloud Monitoring mass-download alert payload.

Usage (PowerShell):
    $env:GEMINI_API_KEY="AIza..."
    $env:GROQ_API_KEY="gsk_..."
    $env:OPENAI_API_KEY="sk-..."
    python test_groq_fallback.py
"""

import json
import os
import sys
import time

import requests


# -- Provider endpoints --
PROVIDERS = {
    "gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "env_key": "GEMINI_API_KEY",
    },
    "groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "env_key": "GROQ_API_KEY",
    },
    "openai": {
        "url": "https://api.openai.com/v1/chat/completions",
        "env_key": "OPENAI_API_KEY",
    },
}

# -- Models to benchmark --
MODELS = [
    {"id": "gemini-2.5-flash",                            "name": "Gemini 2.5 Flash",    "params": "Google (thinking)",     "provider": "gemini"},
    {"id": "gemini-3-flash-preview",                      "name": "Gemini 3 Flash",      "params": "Google (preview)",      "provider": "gemini"},
    {"id": "llama-3.3-70b-versatile",                     "name": "Llama 3.3 70B",       "params": "70B dense",             "provider": "groq"},
    {"id": "qwen/qwen3-32b",                              "name": "Qwen 3 32B",          "params": "32B dense",             "provider": "groq"},
    {"id": "openai/gpt-oss-120b",                         "name": "GPT OSS 120B",        "params": "120B dense",            "provider": "groq"},
    {"id": "gpt-5.4-mini",                                "name": "GPT-5.4 Mini",        "params": "OpenAI mini",           "provider": "openai"},
]

REQUIRED_FIELDS = {
    "severity", "confidence", "should_escalate",
    "summary", "reason", "recommended_remediation",
    "service_account_email",
}

# -- Simulated Cloud Monitoring Alert Payload --
MOCK_ALERT_PAYLOAD = {
    "incident": {
        "incident_id": "test_demo_001",
        "resource_id": "",
        "resource_name": "linen-flash-490013-u3",
        "resource": {
            "type": "gcs_bucket",
            "labels": {"project_id": "linen-flash-490013-u3"}
        },
        "state": "open",
        "started_at": int(time.time()) - 120,
        "ended_at": None,
        "policy_name": "High Volume GCS Access Detected",
        "condition_name": "Mass download metric exceeds threshold",
        "condition": {
            "conditionThreshold": {
                "filter": 'resource.type = "gcs_bucket" AND metric.type = "logging.googleapis.com/user/mass_download_metric"',
                "comparison": "COMPARISON_GT",
                "thresholdValue": 100
            }
        },
        "observed_value": "142",
        "summary": "The mass_download_metric for GCS buckets exceeded the threshold of 100 (observed value: 142) within a 60-second window.",
        "url": "https://console.cloud.google.com/monitoring/alerting/incidents/test_demo_001?project=linen-flash-490013-u3",
        "documentation": {
            "content": "A service account has downloaded more than 100 files from Cloud Storage in 60 seconds. This may indicate data exfiltration.",
            "subject": "Mass Download Alert"
        },
        "metric": {
            "type": "logging.googleapis.com/user/mass_download_metric",
            "displayName": "Mass Download Metric",
            "labels": {
                "principal_email": "victim-employee@linen-flash-490013-u3.iam.gserviceaccount.com"
            }
        },
        "scoping_project_id": "linen-flash-490013-u3",
        "scoping_project_number": 896513254844
    },
    "version": "1.2"
}


def normalize_for_triage(payload: dict) -> dict:
    incident = payload.get("incident", {})
    metric_labels = incident.get("metric", {}).get("labels", {})
    return {
        "principal_email": metric_labels.get("principal_email", "unknown"),
        "service_account_email": metric_labels.get("principal_email", "unknown"),
        "action": "storage.objects.get (mass download)",
        "resource_name": incident.get("resource_name", "unknown"),
        "event_time": str(incident.get("started_at", "unknown")),
        "alert_policy": incident.get("policy_name", "unknown"),
        "observed_value": incident.get("observed_value", "unknown"),
        "threshold": "100 files / 60 seconds",
        "incident_state": incident.get("state", "unknown"),
        "summary": incident.get("summary", ""),
        "raw_event": payload,
    }


def build_prompt(triage_input: dict) -> str:
    return (
        "You are a SOC triage assistant. Analyze this GCP audit event and return ONLY valid JSON "
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


def call_gemini(api_key: str, model_id: str, prompt: str) -> dict:
    """Call Gemini API (non-OpenAI format) and return result dict."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    start = time.time()
    try:
        response = requests.post(url, params={"key": api_key}, json=body, timeout=60)
        elapsed = time.time() - start

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "elapsed": elapsed,
            }

        data = response.json()
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        if not parts:
            return {"success": False, "error": "No content parts in response", "elapsed": elapsed}

        text = parts[0].get("text", "").strip()
        usage = data.get("usageMetadata", {})

        parsed = json.loads(text)
        missing = [k for k in REQUIRED_FIELDS if k not in parsed]

        return {
            "success": True,
            "elapsed": elapsed,
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "parsed": parsed,
            "missing_fields": missing,
            "actual_model": model_id,
        }
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON: {e}", "elapsed": time.time() - start}
    except Exception as e:
        return {"success": False, "error": str(e), "elapsed": time.time() - start}


def call_model(api_url: str, api_key: str, model_id: str, prompt: str) -> dict:
    """Call any OpenAI-compatible API and return result dict with metadata."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    start = time.time()
    try:
        response = requests.post(api_url, headers=headers, json=body, timeout=60)
        elapsed = time.time() - start

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "elapsed": elapsed,
            }

        data = response.json()
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})

        parsed = json.loads(text)
        missing = [k for k in REQUIRED_FIELDS if k not in parsed]

        return {
            "success": True,
            "elapsed": elapsed,
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "parsed": parsed,
            "missing_fields": missing,
            "actual_model": data.get("model", model_id),
        }
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON: {e}", "elapsed": time.time() - start}
    except Exception as e:
        return {"success": False, "error": str(e), "elapsed": time.time() - start}


def format_telegram_message(incident_id: str, triage: dict) -> str:
    return (
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


def print_separator(char="=", length=75):
    print(char * length)


def main():
    # -- Check API keys --
    api_keys = {}
    missing_providers = []
    for pname, pconf in PROVIDERS.items():
        key = os.getenv(pconf["env_key"], "").strip()
        if key:
            api_keys[pname] = key
        else:
            missing_providers.append(f"  {pname}: $env:{pconf['env_key']}")

    if not api_keys:
        print("[FAIL] No API keys found. Set at least one:")
        for m in missing_providers:
            print(m)
        sys.exit(1)

    print_separator()
    print(" AI MODEL COMPARISON - SOC Triage Benchmark")
    print(" Providers: " + ", ".join(f"{p.upper()} [OK]" if p in api_keys else f"{p.upper()} [SKIP]" for p in PROVIDERS))
    print_separator()

    if missing_providers:
        print("\n[INFO] Some providers have no API key (will be skipped):")
        for m in missing_providers:
            print(m)

    # Prepare payload
    triage_input = normalize_for_triage(MOCK_ALERT_PAYLOAD)
    prompt = build_prompt(triage_input)
    print(f"\n[SCENARIO] Mass download alert: 142 files in 60s (threshold: 100)")
    print(f"[SA] victim-employee@linen-flash-490013-u3.iam.gserviceaccount.com")
    print(f"[PROMPT] {len(prompt)} characters\n")

    results = []

    for i, model in enumerate(MODELS, 1):
        provider_name = model["provider"]
        provider_conf = PROVIDERS[provider_name]

        # Skip if no API key for this provider
        if provider_name not in api_keys:
            print_separator("-")
            print(f" [{i}/{len(MODELS)}] {model['name']}  ({model['params']})  [{provider_name.upper()}]")
            print_separator("-")
            print(f"  Status:     SKIPPED (no {provider_conf['env_key']})")
            print()
            results.append({
                "model_name": model["name"],
                "model_id": model["id"],
                "provider": provider_name,
                "success": False,
                "error": "SKIPPED",
                "elapsed": 0,
            })
            continue

        print_separator("-")
        print(f" [{i}/{len(MODELS)}] {model['name']}  ({model['params']})  [{provider_name.upper()}]")
        print(f"        Model ID: {model['id']}")
        print_separator("-")

        # Dispatch to the correct API caller
        if provider_name == "gemini":
            result = call_gemini(
                api_key=api_keys[provider_name],
                model_id=model["id"],
                prompt=prompt,
            )
        else:
            result = call_model(
                api_url=provider_conf["url"],
                api_key=api_keys[provider_name],
                model_id=model["id"],
                prompt=prompt,
            )
        result["model_name"] = model["name"]
        result["model_id"] = model["id"]
        result["provider"] = provider_name
        results.append(result)

        if result["success"]:
            parsed = result["parsed"]
            print(f"  Status:     OK")
            print(f"  Speed:      {result['elapsed']:.2f}s")
            print(f"  Tokens:     {result['prompt_tokens']} in + {result['completion_tokens']} out")
            print(f"  Fields:     {len(REQUIRED_FIELDS) - len(result['missing_fields'])}/{len(REQUIRED_FIELDS)} OK", end="")
            if result["missing_fields"]:
                print(f"  (missing: {result['missing_fields']})")
            else:
                print()
            print(f"  Severity:   {parsed.get('severity', 'N/A')}")
            print(f"  Confidence: {parsed.get('confidence', 'N/A')}")
            print(f"  Escalate:   {parsed.get('should_escalate', 'N/A')}")
            print(f"  SA Email:   {parsed.get('service_account_email', 'N/A')}")
            print(f"  Summary:    {str(parsed.get('summary', 'N/A'))[:80]}")
            print(f"  Reason:     {str(parsed.get('reason', 'N/A'))[:80]}")
            print(f"  Remediation:{str(parsed.get('recommended_remediation', 'N/A'))[:80]}")
        else:
            print(f"  Status:     FAILED")
            print(f"  Error:      {result['error'][:200]}")
            if result['elapsed'] > 0:
                print(f"  Time:       {result['elapsed']:.2f}s")

        print()

    # -- Summary Table --
    print_separator("=")
    print(" COMPARISON SUMMARY")
    print_separator("=")

    header = f"{'Model':<22} {'Provider':>8} {'Speed':>7} {'Tokens':>8} {'Fields':>7} {'Severity':>10} {'Conf':>6} {'Status':>8}"
    print(header)
    print("-" * len(header))

    for r in results:
        prov = r.get("provider", "?").upper()[:5]
        if r["success"]:
            p = r["parsed"]
            fields = f"{len(REQUIRED_FIELDS) - len(r['missing_fields'])}/{len(REQUIRED_FIELDS)}"
            print(
                f"{r['model_name']:<22} "
                f"{prov:>8} "
                f"{r['elapsed']:>6.2f}s "
                f"{r['prompt_tokens'] + r['completion_tokens']:>7} "
                f"{fields:>7} "
                f"{str(p.get('severity', '-')):>10} "
                f"{str(p.get('confidence', '-')):>6} "
                f"{'OK':>8}"
            )
        else:
            status = "SKIP" if r["error"] == "SKIPPED" else "FAIL"
            print(
                f"{r['model_name']:<22} "
                f"{prov:>8} "
                f"{r['elapsed']:>6.2f}s "
                f"{'---':>7} "
                f"{'---':>7} "
                f"{'---':>10} "
                f"{'---':>6} "
                f"{status:>8}"
            )

    print("-" * len(header))

    # Recommend best
    successful = [r for r in results if r["success"] and not r["missing_fields"]]
    if successful:
        fastest = min(successful, key=lambda r: r["elapsed"])
        print(f"\n[FASTEST]  {fastest['model_name']} ({fastest['elapsed']:.2f}s) [{fastest['provider'].upper()}]")

        best_severity = [r for r in successful if r["parsed"].get("severity") in ("HIGH", "CRITICAL")]
        if best_severity:
            smartest = max(best_severity, key=lambda r: float(r["parsed"].get("confidence", 0)))
            print(f"[SMARTEST] {smartest['model_name']} (severity={smartest['parsed']['severity']}, confidence={smartest['parsed']['confidence']}) [{smartest['provider'].upper()}]")

        # Best overall = HIGH/CRITICAL severity + fastest among those
        high_sev = [r for r in successful if r["parsed"].get("severity") in ("HIGH", "CRITICAL")]
        if high_sev:
            best_overall = min(high_sev, key=lambda r: r["elapsed"])
            print(f"\n[BEST FALLBACK] {best_overall['model_name']} ({best_overall['model_id']}) [{best_overall['provider'].upper()}]")
            print(f"  -> Speed: {best_overall['elapsed']:.2f}s | Severity: {best_overall['parsed']['severity']} | Confidence: {best_overall['parsed']['confidence']}")
    else:
        print("\n[WARN] No model produced a fully valid response.")

    print_separator()
    print("[DONE] Benchmark complete!")


if __name__ == "__main__":
    main()
