"""Optional VirusTotal domain reputation lookup for ScamAirbag.

Uses only the domain hostname (never URL paths, query strings, or fragments).
The public VirusTotal API is limited and restricted to non-commercial use;
configure VIRUSTOTAL_API_KEY only where its current terms permit this use.
A missing report is UNKNOWN, never a clean verdict.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict
from urllib.parse import quote, urlsplit

import requests

from schemas import EvidenceProvenance, ToolExecutionResult


def virustotal_is_configured() -> bool:
    return bool(os.getenv("VIRUSTOTAL_API_KEY"))


def _domain(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    if not host or "." not in host or len(host) > 253:
        raise ValueError("A valid public hostname is required.")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
        raise ValueError("Invalid hostname.")
    return host.removeprefix("www.")


def check_domain_reputation(domain_or_url: str) -> ToolExecutionResult:
    name = "threat_intelligence"
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return ToolExecutionResult(
            tool_name=name, status="NOT_APPLICABLE",
            provenance=EvidenceProvenance.UNAVAILABLE,
            error_code="VIRUSTOTAL_NOT_CONFIGURED",
            error_message="External reputation lookup is not configured.",
        )
    try:
        domain = _domain(domain_or_url)
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{quote(domain, safe='.-')}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "8")),
        )
        if response.status_code == 404:
            return ToolExecutionResult(
                tool_name=name, status="SUCCESS",
                provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
                data={"domain": domain, "record_found": False,
                       "verdict": "NO_REPORT", "source": "VirusTotal"},
            )
        response.raise_for_status()
        payload: Dict[str, Any] = response.json().get("data", {}).get("attributes", {})
        stats = payload.get("last_analysis_stats") or {}
        categories = payload.get("categories") or {}
        stats = {key: int(stats.get(key) or 0) for key in
                 ("malicious", "suspicious", "harmless", "undetected", "timeout")}
        total = sum(stats.values())
        return ToolExecutionResult(
            tool_name=name, status="SUCCESS",
            provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
            data={
                "domain": domain, "record_found": True, "source": "VirusTotal",
                "reputation": payload.get("reputation"),
                "last_analysis_stats": stats,
                "last_analysis_date": payload.get("last_analysis_date"),
                "analysis_engines_reporting": total,
                "categories": {str(k): str(v) for k, v in list(categories.items())[:5]},
                "whois_date": payload.get("whois_date"),
            },
        )
    except requests.Timeout:
        code, message = "THREAT_INTEL_TIMEOUT", "VirusTotal lookup timed out."
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        code = "THREAT_INTEL_RATE_LIMIT" if status == 429 else f"THREAT_INTEL_HTTP_{status}"
        message = f"VirusTotal returned HTTP {status}."
    except requests.RequestException as exc:
        code, message = "THREAT_INTEL_NETWORK_ERROR", type(exc).__name__
    except Exception as exc:
        code, message = "THREAT_INTEL_LOOKUP_FAILED", str(exc)[:200]
    return ToolExecutionResult(
        tool_name=name, status="FAILED", provenance=EvidenceProvenance.UNAVAILABLE,
        error_code=code, error_message=message,
    )
