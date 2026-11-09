"""Optional Elastic-backed historical pattern intelligence for ScamAirbag.

Only deliberately minimized, user-consented investigation summaries are indexed.
No raw messages, email addresses, PayPal IDs, invoice notes, or recipient details
are stored. Search results are contextual similarity signals, never proof of fraud.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from schemas import EvidenceProvenance, ToolExecutionResult


def elastic_is_configured() -> bool:
    return bool(os.getenv("ELASTICSEARCH_URL") and os.getenv("ELASTIC_API_KEY"))


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"ApiKey {os.environ['ELASTIC_API_KEY']}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base_url() -> str:
    return os.environ["ELASTICSEARCH_URL"].rstrip("/")


def _index_name() -> str:
    value = os.getenv("ELASTIC_INDEX", "scamairbag-investigations")
    if not value.replace("-", "").replace("_", "").isalnum():
        raise ValueError("ELASTIC_INDEX contains unsupported characters.")
    return value


def _ensure_index() -> None:
    index_url = f"{_base_url()}/{quote(_index_name(), safe='')}"
    timeout = float(os.getenv("ELASTIC_TIMEOUT_SECONDS", "5"))
    exists = requests.head(index_url, headers=_headers(), timeout=timeout)
    if exists.status_code == 404:
        created = requests.put(
            index_url, headers=_headers(), timeout=timeout,
            json={"mappings": {"properties": {
                "case_id": {"type": "keyword"},
                "domains": {"type": "keyword"},
                "indicator_ids": {"type": "keyword"},
                "risk_band": {"type": "keyword"},
                "created_at": {"type": "date"},
            }}},
        )
        # A concurrent first request may create the index between HEAD and PUT.
        if created.status_code not in (200, 201):
            try:
                error_payload = created.json()
            except ValueError:
                error_payload = {}
            error_type = (error_payload.get("error") or {}).get("type")
            if error_type != "resource_already_exists_exception":
                created.raise_for_status()
    else:
        exists.raise_for_status()


def _safe_domain(domain: str) -> str:
    # The domain is already normalized by the domain-intelligence tool. Keep a
    # conservative character set here as a second boundary.
    value = domain.strip().lower().rstrip(".")
    if not value or len(value) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in value):
        raise ValueError("Invalid domain supplied to historical intelligence.")
    return value


def search_similar_cases(domain: str) -> ToolExecutionResult:
    """Search prior opt-in case summaries for an exact domain or shared signals."""
    name = "historical_pattern_search"
    if not elastic_is_configured():
        return ToolExecutionResult(
            tool_name=name, status="NOT_APPLICABLE",
            provenance=EvidenceProvenance.UNAVAILABLE,
            error_code="ELASTIC_NOT_CONFIGURED",
            error_message="Historical intelligence is not configured.",
        )
    try:
        domain = _safe_domain(domain)
        _ensure_index()
        response = requests.post(
            f"{_base_url()}/{quote(_index_name(), safe='')}/_search",
            headers=_headers(), timeout=float(os.getenv("ELASTIC_TIMEOUT_SECONDS", "5")),
            json={
                "size": 5,
                "_source": ["case_id", "domains", "indicator_ids", "risk_band", "created_at"],
                "query": {"term": {"domains": domain}},
                "sort": [{"created_at": {"order": "desc"}}],
            },
        )
        response.raise_for_status()
        payload = response.json()
        hits = payload.get("hits", {}).get("hits", [])
        cases = []
        for hit in hits:
            source = hit.get("_source") or {}
            cases.append({
                "case_id": source.get("case_id"),
                "matching_domains": [domain],
                "indicator_ids": source.get("indicator_ids") or [],
                "risk_band": source.get("risk_band", "UNKNOWN"),
                "created_at": source.get("created_at"),
            })
        return ToolExecutionResult(
            tool_name=name, status="SUCCESS",
            provenance=EvidenceProvenance.HISTORICAL_CASE,
            data={"domain": domain, "match_count": len(cases), "cases": cases},
        )
    except requests.Timeout:
        return ToolExecutionResult(
            tool_name=name, status="FAILED", provenance=EvidenceProvenance.UNAVAILABLE,
            error_code="ELASTIC_TIMEOUT", error_message="Historical search timed out.",
        )
    except requests.RequestException as exc:
        return ToolExecutionResult(
            tool_name=name, status="FAILED", provenance=EvidenceProvenance.UNAVAILABLE,
            error_code="ELASTIC_REQUEST_FAILED",
            error_message=f"Historical search failed ({type(exc).__name__}).",
        )
    except Exception as exc:
        return ToolExecutionResult(
            tool_name=name, status="FAILED", provenance=EvidenceProvenance.UNAVAILABLE,
            error_code="ELASTIC_SEARCH_FAILED",
            error_message=f"Historical search failed ({type(exc).__name__}).",
        )


def store_opt_in_case(
    domains: List[str], indicator_ids: List[str], risk_score: int,
) -> Optional[str]:
    """Index a minimized case only when the user explicitly opted in."""
    if not elastic_is_configured() or os.getenv("ELASTIC_STORE_CASES", "false").lower() != "true":
        return None
    safe_domains = sorted({_safe_domain(item) for item in domains if item})[:10]
    safe_indicators = sorted({str(item)[:80] for item in indicator_ids if item})[:30]
    if not safe_domains and not safe_indicators:
        return None
    case_id = uuid.uuid4().hex
    risk_band = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 35 else "LOW"
    document = {
        "case_id": case_id,
        "domains": safe_domains,
        "indicator_ids": safe_indicators,
        "risk_band": risk_band,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _ensure_index()
    response = requests.put(
        f"{_base_url()}/{quote(_index_name(), safe='')}/_doc/{case_id}",
        headers=_headers(), timeout=float(os.getenv("ELASTIC_TIMEOUT_SECONDS", "5")),
        json=document,
    )
    response.raise_for_status()
    return case_id
