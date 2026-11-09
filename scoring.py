"""
scoring.py - Deterministic risk, coverage, and confidence calculations.

This module contains no LLM calls. It converts evidence collected by tools.py
into Findings, SourceOutcome records, and an AirbagScorecard.

Public entry point:
    score_investigation(input_context, extracted_entities, tool_results,
                        source_outcomes=None)

Important:
- A missing or failed lookup never adds fraud risk by itself.
- Coverage is calculated only across checks marked applicable.
- A low risk score is not proof that a payment is safe.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from elastic_intelligence import elastic_is_configured

from schemas import (
    AirbagScorecard,
    EvidenceProvenance,
    ExtractedEntities,
    Finding,
    InvestigationInput,
    RecommendedAction,
    RiskLevel,
    SourceOutcome,
    ToolExecutionResult,
)

# Keep weights centralized so changes can be reviewed and tested.
RULE_WEIGHTS = {
    "SELLER_EMAIL_MISMATCH": 45,
    "NEW_DOMAIN": 25,
    "COERCION_TACTIC": 15,
    "HIGH_PRESSURE_LANGUAGE": 10,
    "UNUSUAL_PAYMENT_INSTRUCTION": 25,
    "DOMAIN_DOES_NOT_RESOLVE": 0,
}

SUCCESS_STATUSES = {"SUCCESS", "VERIFIED", "COMPLETED"}
FAILED_STATUSES = {"FAILED", "ERROR", "TIMEOUT"}
SKIPPED_STATUSES = {"SKIPPED", "NOT_APPLICABLE"}


def _normalize_email(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().casefold()
    # Basic sanity check; this is normalization, not full email validation.
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        return None
    return value


def _risk_level(score: int) -> RiskLevel:
    if score <= 0:
        return RiskLevel.INFO
    if score < 20:
        return RiskLevel.LOW
    if score < 45:
        return RiskLevel.MEDIUM
    if score < 70:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _make_finding(
    rule_id: str,
    description: str,
    severity: RiskLevel,
    provenance: EvidenceProvenance,
    impact: int,
    evidence: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        description=description,
        severity=severity,
        provenance=provenance,
        risk_impact=impact,
        supporting_evidence=evidence[:1000],
    )


def _result_by_name(
    tool_results: Sequence[ToolExecutionResult], tool_name: str
) -> Optional[ToolExecutionResult]:
    # Prefer the most recent result if a tool was retried.
    for result in reversed(tool_results):
        if result.tool_name == tool_name:
            return result
    return None


def _entities_from_result(
    tool_results: Sequence[ToolExecutionResult],
) -> Optional[ExtractedEntities]:
    result = _result_by_name(tool_results, "extract_message_context")
    if not result or result.status != "SUCCESS":
        return None
    raw = result.data.get("entities")
    if isinstance(raw, ExtractedEntities):
        return raw
    if isinstance(raw, dict):
        try:
            return ExtractedEntities.model_validate(raw)
        except Exception:
            return None
    return None


def _paypal_seller_email(
    tool_results: Sequence[ToolExecutionResult],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Return the best verified seller email and its source.

    Invoice seller email comes from invoicer.email_address. Order payee email
    is also a seller-side field. Subscription subscriber email is the payer,
    not the seller, so it must never be used for seller identity comparison.
    """
    invoice = _result_by_name(tool_results, "paypal_invoice")
    if invoice and invoice.status == "SUCCESS":
        email = _normalize_email(invoice.data.get("seller_email"))
        if email:
            return email, "PayPal invoice invoicer.email_address"

    order = _result_by_name(tool_results, "paypal_order")
    if order and order.status == "SUCCESS":
        for unit in order.data.get("purchase_units", []) or []:
            email = _normalize_email(unit.get("payee_email"))
            if email:
                return email, "PayPal order purchase_units.payee.email_address"

    return None, None


def _source_outcome(
    source_name: str,
    applicable: bool,
    status: str,
    provenance: EvidenceProvenance,
    error_code: Optional[str] = None,
) -> SourceOutcome:
    return SourceOutcome(
        source_name=source_name,
        applicable=applicable,
        status=status,
        provenance=provenance,
        error_code=error_code,
    )


def _domain_key(value: Optional[str]) -> str:
    if not value:
        return ""
    value = value.strip().lower().rstrip(".")
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value.removeprefix("www.")


def _matching_domain_result(
    tool_results: Sequence[ToolExecutionResult], domain: str,
) -> Optional[ToolExecutionResult]:
    target = _domain_key(domain)
    for result in reversed(tool_results):
        if result.tool_name == "domain_intelligence":
            candidate = result.data.get("domain") or result.data.get("requested_input")
            if _domain_key(candidate) == target:
                return result
    return None


def build_source_outcomes(
    input_context: InvestigationInput,
    extracted_entities: Optional[ExtractedEntities],
    tool_results: Sequence[ToolExecutionResult],
) -> List[SourceOutcome]:
    """Build coverage at the granularity of each applicable evidence check."""
    outcomes: List[SourceOutcome] = []

    extraction = _result_by_name(tool_results, "extract_message_context")
    message_applicable = bool(input_context.user_text and input_context.user_text.strip())
    if not message_applicable:
        outcomes.append(_source_outcome("message_context", False, "NOT_APPLICABLE",
                                        EvidenceProvenance.UNAVAILABLE, "NO_MESSAGE_TEXT"))
    elif extraction is None:
        outcomes.append(_source_outcome("message_context", True, "SKIPPED",
                                        EvidenceProvenance.UNAVAILABLE, "EXTRACTION_NOT_ATTEMPTED"))
    else:
        outcomes.append(_source_outcome(
            "message_context", True, extraction.status, extraction.provenance,
            extraction.error_code,
        ))

    hint = (input_context.identifier_hint or "UNKNOWN").strip().upper()
    endpoint_by_hint = {
        "INVOICE": ("paypal_invoice", "invoice"),
        "ORDER": ("paypal_order", "order"),
        "SUBSCRIPTION": ("paypal_subscription", "subscription"),
    }
    identifier = input_context.identifier
    if not identifier and extracted_entities and extracted_entities.extracted_identifier:
        identifier = extracted_entities.extracted_identifier
        hint = (extracted_entities.identifier_hint or "UNKNOWN").strip().upper()
    if identifier and hint in endpoint_by_hint:
        tool_name, label = endpoint_by_hint[hint]
        result = _result_by_name(tool_results, tool_name)
        outcomes.append(_source_outcome(
            f"paypal_{label}", True,
            result.status if result else "SKIPPED",
            result.provenance if result else EvidenceProvenance.UNAVAILABLE,
            result.error_code if result else "PAYPAL_LOOKUP_NOT_ATTEMPTED",
        ))
    elif identifier:
        outcomes.append(_source_outcome(
            "paypal_identifier", True, "SKIPPED", EvidenceProvenance.UNAVAILABLE,
            "IDENTIFIER_TYPE_UNKNOWN",
        ))
    else:
        outcomes.append(_source_outcome(
            "paypal_identifier", False, "NOT_APPLICABLE", EvidenceProvenance.UNAVAILABLE,
            "NO_IDENTIFIER",
        ))

    domains = list(dict.fromkeys(extracted_entities.detected_domains if extracted_entities else []))
    if not domains:
        outcomes.append(_source_outcome(
            "domain_intelligence", False, "NOT_APPLICABLE", EvidenceProvenance.UNAVAILABLE,
            "NO_DOMAIN_DETECTED",
        ))
        outcomes.append(_source_outcome(
            "elastic_historical_intelligence", False, "NOT_APPLICABLE",
            EvidenceProvenance.UNAVAILABLE, "NO_DOMAIN_DETECTED",
        ))
    else:
        for domain in domains:
            result = _matching_domain_result(tool_results, domain)
            dns_status = (result.data.get("dns_status") if result else None)
            if dns_status is None and result:
                # Backward compatibility with older result records.
                legacy = result.data.get("domain_status")
                dns_status = "SUCCESS" if legacy in {
                    "RESOLVED", "NXDOMAIN", "WHOIS_TIMEOUT", "WHOIS_UNAVAILABLE"
                } else "FAILED"
            dns_provenance = result.provenance if result else EvidenceProvenance.UNAVAILABLE
            dns_state = "SKIPPED" if result is None else (
                "SUCCESS" if dns_status in {"SUCCESS", "NXDOMAIN"} else "FAILED"
            )
            outcomes.append(_source_outcome(
                f"domain_dns:{_domain_key(domain)}", True, dns_state,
                dns_provenance, result.error_code if result and dns_state == "FAILED" else None,
            ))

            whois_status = result.data.get("whois_status") if result else None
            if whois_status is None and result:
                legacy = result.data.get("domain_status")
                whois_status = (
                    "SUCCESS" if result.data.get("whois_available") else
                    "FAILED" if legacy in {"WHOIS_TIMEOUT", "WHOIS_UNAVAILABLE"} else
                    "NOT_APPLICABLE" if legacy == "NXDOMAIN" else "SKIPPED"
                )
            if whois_status == "NOT_APPLICABLE":
                outcomes.append(_source_outcome(
                    f"domain_whois:{_domain_key(domain)}", False, "NOT_APPLICABLE",
                    EvidenceProvenance.UNAVAILABLE, "DNS_DID_NOT_RESOLVE",
                ))
            else:
                whois_state = "SKIPPED" if result is None or whois_status == "NOT_CHECKED" else (
                    "SUCCESS" if whois_status == "SUCCESS" else "FAILED"
                )
                outcomes.append(_source_outcome(
                    f"domain_whois:{_domain_key(domain)}", True, whois_state,
                    EvidenceProvenance.OBSERVED_EXTERNAL if whois_state == "SUCCESS"
                    else EvidenceProvenance.UNAVAILABLE,
                    result.data.get("whois_error") if result else "DOMAIN_CHECK_NOT_ATTEMPTED",
                ))

            if elastic_is_configured():
                history = next((item for item in reversed(tool_results)
                                if item.tool_name == "historical_pattern_search"
                                and _domain_key(item.data.get("domain")) == _domain_key(domain)), None)
                outcomes.append(_source_outcome(
                    f"elastic_history:{_domain_key(domain)}", True,
                    history.status if history else "SKIPPED",
                    history.provenance if history else EvidenceProvenance.UNAVAILABLE,
                    history.error_code if history else "HISTORICAL_SEARCH_NOT_ATTEMPTED",
                ))
            else:
                outcomes.append(_source_outcome(
                    f"elastic_history:{_domain_key(domain)}", False, "NOT_APPLICABLE",
                    EvidenceProvenance.UNAVAILABLE, "ELASTIC_NOT_CONFIGURED",
                ))

    return outcomes


def calculate_coverage(source_outcomes: Sequence[SourceOutcome]) -> int:
    """
    Coverage = completed applicable checks / all applicable checks * 100.

    NOT_APPLICABLE checks are excluded. SKIPPED and FAILED checks remain in
    the denominator, preventing incomplete investigations from looking
    complete. If no checks apply, return 0 (not 100).
    """
    applicable = [item for item in source_outcomes if item.applicable]
    if not applicable:
        return 0
    completed = sum(
        1 for item in applicable
        if item.status.upper() in SUCCESS_STATUSES
    )
    return round((completed / len(applicable)) * 100)


def calculate_confidence(
    source_outcomes: Sequence[SourceOutcome],
    findings: Sequence[Finding],
) -> str:
    """
    Confidence reflects evidence quality and coverage, not the risk score.

    HIGH requires strong coverage plus at least one verified PayPal source.
    MEDIUM requires reasonable coverage and some external/verified evidence.
    Otherwise confidence is LOW.
    """
    coverage = calculate_coverage(source_outcomes)
    successful = [
        item for item in source_outcomes
        if item.applicable and item.status.upper() in SUCCESS_STATUSES
    ]
    has_verified_paypal = any(
        item.provenance == EvidenceProvenance.VERIFIED_PAYPAL
        for item in successful
    )
    has_observed_external = any(
        item.provenance == EvidenceProvenance.OBSERVED_EXTERNAL
        for item in successful
    )

    if coverage >= 80 and has_verified_paypal:
        return "HIGH"
    if coverage >= 50 and (has_verified_paypal or has_observed_external):
        return "MEDIUM"
    return "LOW"


def _build_findings(
    entities: Optional[ExtractedEntities],
    tool_results: Sequence[ToolExecutionResult],
) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    unverified_claims: List[str] = []

    if entities:
        # Compare only claimed seller email to a verified seller-side PayPal
        # email. Never compare it to the invoice recipient or subscriber email.
        claimed_email = _normalize_email(entities.claimed_seller_email)
        verified_email, verified_source = _paypal_seller_email(tool_results)
        if claimed_email and verified_email and claimed_email != verified_email:
            findings.append(_make_finding(
                "SELLER_EMAIL_MISMATCH",
                "The seller email stated in the submitted message differs from the seller email returned by PayPal.",
                RiskLevel.HIGH,
                EvidenceProvenance.VERIFIED_PAYPAL,
                RULE_WEIGHTS["SELLER_EMAIL_MISMATCH"],
                f"Message claim: {claimed_email}; {verified_source}: {verified_email}.",
            ))
        elif claimed_email and not verified_email:
            unverified_claims.append(
                f"Claimed seller email could not be compared with a verified PayPal seller email: {claimed_email}"
            )

        # Tactic labels are generated by the extraction model, so preserve
        # AI_INFERRED provenance and quote-based evidence.
        quote_text = " | ".join(entities.raw_evidence_quotes) or (
            "The extraction model identified a coercion tactic; no supporting quote was returned."
        )
        tactic_weights = {
            "artificial_deadline": 15,
            "friends_and_family_diversion": 25,
            "threat_of_cancellation": 15,
            "secrecy_demanded": 20,
            "threat_or_intimidation": 20,
        }
        seen_tactics = set()
        for tactic in entities.coercion_tactics:
            key = tactic.strip().casefold()
            if key in seen_tactics:
                continue
            seen_tactics.add(key)
            weight = tactic_weights.get(key, RULE_WEIGHTS["COERCION_TACTIC"])
            findings.append(_make_finding(
                "COERCION_TACTIC",
                f"The message contains a potential pressure tactic: {tactic.replace('_', ' ')}.",
                _risk_level(weight),
                EvidenceProvenance.AI_INFERRED,
                weight,
                quote_text,
            ))

        if entities.urgency_score >= 8 and not entities.coercion_tactics:
            findings.append(_make_finding(
                "HIGH_PRESSURE_LANGUAGE",
                "The message was assessed as using unusually high urgency or pressure.",
                RiskLevel.LOW,
                EvidenceProvenance.AI_INFERRED,
                RULE_WEIGHTS["HIGH_PRESSURE_LANGUAGE"],
                quote_text,
            ))

        instruction_weights = {
            "demands_gift_card": 25,
            "third_party_wire": 15,
            "secrecy_demanded": 20,
            "friends_and_family_diversion": 25,
        }
        for instruction in sorted(set(entities.unusual_payment_instructions)):
            weight = instruction_weights.get(
                instruction.strip().casefold(),
                RULE_WEIGHTS["UNUSUAL_PAYMENT_INSTRUCTION"],
            )
            findings.append(_make_finding(
                "UNUSUAL_PAYMENT_INSTRUCTION",
                f"The message includes a potentially unusual payment instruction: {instruction.replace('_', ' ')}.",
                _risk_level(weight),
                EvidenceProvenance.AI_INFERRED,
                weight,
                quote_text,
            ))

    # Domain age and historical matches are contextual signals, not proof.
    domain_results = [item for item in tool_results if item.tool_name == "domain_intelligence"]
    for domain_result in domain_results:
        age = domain_result.data.get("domain_age_days")
        domain = domain_result.data.get("domain") or domain_result.data.get("requested_input")
        if isinstance(age, int) and age < 14:
            findings.append(_make_finding(
                "NEW_DOMAIN",
                "The checked domain appears to have been registered within the last 14 days. A newly registered domain is a caution signal, not proof of fraud.",
                RiskLevel.MEDIUM, EvidenceProvenance.OBSERVED_EXTERNAL,
                RULE_WEIGHTS["NEW_DOMAIN"],
                f"Domain: {domain}; observed registration age: {age} days.",
            ))
        dns_status = domain_result.data.get("dns_status") or domain_result.data.get("domain_status")
        if dns_status == "NXDOMAIN":
            findings.append(_make_finding(
                "DOMAIN_DOES_NOT_RESOLVE",
                "The domain did not resolve during the DNS check. This may indicate a typo, expired domain, temporary DNS issue, or other availability problem; it is not proof of fraud.",
                RiskLevel.INFO, EvidenceProvenance.OBSERVED_EXTERNAL,
                RULE_WEIGHTS["DOMAIN_DOES_NOT_RESOLVE"],
                f"Domain: {domain or 'unknown'}; DNS outcome: NXDOMAIN.",
            ))

    for history in (item for item in tool_results if item.tool_name == "historical_pattern_search"):
        count = int(history.data.get("match_count") or 0)
        if history.status == "SUCCESS" and count:
            domain = history.data.get("domain") or "the checked domain"
            findings.append(_make_finding(
                "HISTORICAL_PATTERN_MATCH",
                f"Elastic found {count} prior opt-in investigation record(s) containing this exact domain. This is historical context, not proof that the current request is fraudulent.",
                RiskLevel.INFO, EvidenceProvenance.HISTORICAL_CASE, 0,
                f"Domain: {domain}; matching historical records: {count}.",
            ))

    return findings, unverified_claims


def _recommend_action(
    risk_score: int,
    confidence: str,
) -> RecommendedAction:
    if risk_score >= 70:
        return RecommendedAction.ABORT_PAYMENT
    if risk_score >= 35 or confidence == "LOW":
        return RecommendedAction.PROCEED_WITH_MANUAL_VERIFICATION
    return RecommendedAction.NO_MAJOR_RISK_INDICATORS_FOUND


def score_investigation(
    input_context: InvestigationInput,
    extracted_entities: Optional[ExtractedEntities],
    tool_results: Sequence[ToolExecutionResult],
    source_outcomes: Optional[Sequence[SourceOutcome]] = None,
) -> Tuple[AirbagScorecard, List[SourceOutcome]]:
    """
    Calculate a scorecard and return the source outcomes used for coverage.

    Pass explicit source_outcomes from the agent when it has determined
    applicability more precisely than can be inferred from the request alone.
    """
    if extracted_entities is None:
        extracted_entities = _entities_from_result(tool_results)

    outcomes = list(source_outcomes) if source_outcomes is not None else build_source_outcomes(
        input_context, extracted_entities, tool_results
    )

    findings, unverified_claims = _build_findings(extracted_entities, tool_results)

    # Cap the sum at 100. Repeated indicators can contribute, so callers should
    # avoid emitting duplicate findings for the same underlying evidence.
    risk_score = min(100, sum(item.risk_impact for item in findings))
    coverage_score = calculate_coverage(outcomes)
    confidence = calculate_confidence(outcomes, findings)
    action = _recommend_action(risk_score, confidence)

    if action == RecommendedAction.ABORT_PAYMENT:
        summary = (
            "Multiple or high-impact risk indicators were identified. "
            "Do not make the payment unless the concerns are independently resolved."
        )
    elif action == RecommendedAction.PROCEED_WITH_MANUAL_VERIFICATION:
        summary = (
            "The investigation found risk indicators or insufficient evidence. "
            "Verify the seller and payment details through an independent, trusted channel before deciding."
        )
    else:
        summary = (
            "No major risk indicators were identified in the checks completed. "
            "This is not a guarantee that the payment or seller is safe."
        )

    if coverage_score < 100:
        summary += f" Investigation coverage: {coverage_score}% of applicable checks completed."

    scorecard = AirbagScorecard(
        risk_score=risk_score,
        coverage_score=coverage_score,
        confidence_level=confidence,
        recommended_action=action,
        executive_summary=summary,
        findings=findings,
        unverified_claims=unverified_claims,
    )
    return scorecard, outcomes
