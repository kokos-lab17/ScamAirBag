"""Tamper-evident, privacy-minimized evidence manifests.

The manifest hashes the exact evidence projection shown to the user. It proves
that the report payload has not changed relative to its manifest; it does NOT
cryptographically sign PayPal or third-party source responses.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from schemas import InvestigationTrace


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _public_evidence(tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Project only fields suitable for a user-facing evidence receipt."""
    allowlists = {
        "paypal_invoice": (
            "invoice_id", "status", "seller_name", "seller_email",
            "currency_code", "amount", "payment_terms", "due_date",
        ),
        "paypal_order": ("order_id", "status", "intent", "purchase_units"),
        "paypal_subscription": (
            "subscription_id", "status", "plan_id", "plan_name", "plan_status",
            "product_id", "plan_details_status", "billing_cycles", "start_time",
            "next_billing_time", "failed_payments_count", "outstanding_balance",
            "last_payment", "cycle_executions", "auto_bill_outstanding", "setup_fee", "taxes",
        ),
        "domain_intelligence": (
            "domain", "dns_status", "whois_status", "domain_age_days",
            "creation_date", "tls_status", "tls_issuer", "tls_not_after",
            "tls_days_until_expiry", "tls_hostname_verified",
            "lookalike_observation", "resolved_ips",
        ),
        "link_redirect_inspection": (
            "initial_host", "final_host", "redirect_hops",
            "cross_domain_redirect", "https_downgrade",
            "redirect_loop_detected", "redirect_limit_reached",
            "blocked_unsafe_destination", "inspection_method",
        ),
        "email_authentication_headers": (
            "header_parse_status", "authentication_results",
            "received_spf_results", "from_domain", "return_path_domain",
            "dkim_signing_domains", "alignment_observations", "limitations",
        ),
        "threat_intelligence": (
            "domain", "record_found", "source", "reputation",
            "last_analysis_stats", "last_analysis_date",
            "analysis_engines_reporting", "categories",
        ),
        "historical_pattern_search": ("domain", "match_count", "cases"),
    }
    if tool_name == "extract_message_context":
        entities = data.get("entities") or {}
        keys = (
            "claimed_seller_name", "claimed_seller_email", "claimed_recipient_name",
            "claimed_amount", "claimed_currency_code", "claimed_amount_quote",
            "extracted_identifier", "identifier_hint", "detected_domains", "urgency_score",
            "coercion_tactics", "unusual_payment_instructions",
        )
        return {key: entities[key] for key in keys if key in entities and entities[key] not in (None, [], "")}
    if tool_name == "paypal_order":
        units = []
        for unit in data.get("purchase_units") or []:
            if not isinstance(unit, dict):
                continue
            units.append({
                key: unit[key] for key in ("reference_id", "payee_name", "payee_email", "amount", "invoice_id")
                if key in unit and unit[key] is not None
            })
        return {
            key: data[key] for key in ("order_id", "status", "intent")
            if key in data and data[key] is not None
        } | {"purchase_units": units}
    keys = allowlists.get(tool_name, ())
    return {key: data[key] for key in keys if key in data and data[key] is not None}


def build_evidence_manifest(trace: InvestigationTrace, signing_key: str | None = None) -> Dict[str, Any]:
    """Build a deterministic-content manifest with a fresh creation timestamp."""
    records: List[Dict[str, Any]] = []
    for index, step in enumerate(trace.steps, start=1):
        result = step.result
        if result is None:
            continue
        evidence = _public_evidence(result.tool_name, result.data or {})
        payload = {
            "tool_name": result.tool_name,
            "status": result.status,
            "provenance": result.provenance.value,
            "error_code": result.error_code,
            "evidence": evidence,
        }
        records.append({
            "evidence_id": f"EV-{index:03d}",
            **payload,
            "sha256": sha256_json(payload),
        })

    findings = []
    scorecard = trace.final_scorecard
    if scorecard:
        for index, finding in enumerate(scorecard.findings, start=1):
            payload = finding.model_dump(mode="json") if hasattr(finding, "model_dump") else finding.dict()
            findings.append({
                "finding_id": f"F-{index:03d}",
                **payload,
                "sha256": sha256_json(payload),
            })

    created_at = datetime.now(timezone.utc).isoformat()
    integrity_note = (
        "SHA-256 hashes cover the evidence records, findings, and manifest metadata. "
        "When a signing key is configured, the ScamAirbag API also adds an HMAC-SHA256 "
        "server signature so later edits can be detected. This is not a digital signature "
        "from PayPal or external sources; provenance labels describe how ScamAirbag obtained each observation."
    )
    root_payload = {
        "manifest_version": "1.0",
        "created_at": created_at,
        "investigation_status": trace.status,
        "integrity_note": integrity_note,
        "evidence_records": [item["sha256"] for item in records],
        "findings": [item["sha256"] for item in findings],
    }
    root_sha256 = sha256_json(root_payload)
    signature = None
    if signing_key:
        signature = {
            "algorithm": "HMAC-SHA256",
            "signer": "ScamAirbag API",
            "value": hmac.new(signing_key.encode("utf-8"), root_sha256.encode("ascii"), hashlib.sha256).hexdigest(),
        }
    return {
        "manifest_version": "1.0",
        "created_at": created_at,
        "investigation_status": trace.status,
        "evidence_records": records,
        "findings": findings,
        "root_sha256": root_sha256,
        "signature": signature,
        "integrity_note": integrity_note,
    }


def verify_evidence_manifest(manifest: Dict[str, Any], signing_key: str | None = None) -> Dict[str, Any]:
    """Verify all record hashes and the manifest root without trusting supplied hashes."""
    errors: List[str] = []
    records = manifest.get("evidence_records")
    findings = manifest.get("findings")
    if not isinstance(records, list) or not isinstance(findings, list):
        return {"valid": False, "errors": ["Manifest evidence_records/findings must be arrays."]}

    record_hashes = []
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict) or not isinstance(record.get("sha256"), str):
            errors.append(f"Evidence record {index} is malformed.")
            continue
        payload = {key: value for key, value in record.items() if key not in {"evidence_id", "sha256"}}
        actual = sha256_json(payload)
        if actual != record["sha256"]:
            errors.append(f"Evidence record {index} hash mismatch.")
        record_hashes.append(actual)

    finding_hashes = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict) or not isinstance(finding.get("sha256"), str):
            errors.append(f"Finding {index} is malformed.")
            continue
        payload = {key: value for key, value in finding.items() if key not in {"finding_id", "sha256"}}
        actual = sha256_json(payload)
        if actual != finding["sha256"]:
            errors.append(f"Finding {index} hash mismatch.")
        finding_hashes.append(actual)

    root_payload = {
        "manifest_version": manifest.get("manifest_version"),
        "created_at": manifest.get("created_at"),
        "investigation_status": manifest.get("investigation_status"),
        "integrity_note": manifest.get("integrity_note"),
        "evidence_records": record_hashes,
        "findings": finding_hashes,
    }
    calculated_root = sha256_json(root_payload)
    if calculated_root != manifest.get("root_sha256"):
        errors.append("Manifest root hash mismatch.")

    signature = manifest.get("signature")
    signature_status = "UNSIGNED"
    if signature:
        if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
            signature_status = "INVALID_FORMAT"
            errors.append("Manifest signature format is unsupported.")
        elif not signing_key:
            signature_status = "UNVERIFIABLE"
            errors.append("Manifest is signed, but no verification key is configured.")
        else:
            expected_signature = hmac.new(
                signing_key.encode("utf-8"),
                str(manifest.get("root_sha256", "")).encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            supplied_signature = str(signature.get("value") or "")
            if hmac.compare_digest(expected_signature, supplied_signature):
                signature_status = "VERIFIED"
            else:
                signature_status = "INVALID"
                errors.append("Manifest server signature mismatch.")
    return {"valid": not errors, "signature_status": signature_status, "errors": errors,
            "verified_evidence_records": len(record_hashes),
            "verified_findings": len(finding_hashes), "root_sha256": manifest.get("root_sha256")}
