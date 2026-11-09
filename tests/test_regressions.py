import os

import pytest
from pydantic import ValidationError

import agent
import main
import tools
from schemas import (
    AgentDecision, EvidenceProvenance, ExtractedEntities, InvestigationInput,
    InvestigationStep, InvestigationTrace, ToolExecutionResult,
)
from scoring import build_source_outcomes, calculate_coverage


def test_unknown_paypal_identifier_type_is_rejected():
    with pytest.raises(ValidationError):
        main.InvestigationRequest(
            user_text="Please check this payment", identifier="ABC-123",
            identifier_hint="UNKNOWN",
        )


def test_identifier_type_is_required_only_when_identifier_is_present():
    request = main.InvestigationRequest(user_text="Please check this message")
    assert request.identifier_hint == "UNKNOWN"


def test_multiple_domains_reduce_coverage_when_one_is_unchecked(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    entities = ExtractedEntities(detected_domains=["alpha.example", "beta.example"])
    one_domain = ToolExecutionResult(
        tool_name="domain_intelligence", status="SUCCESS",
        provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
        data={"domain": "alpha.example", "dns_status": "SUCCESS", "whois_status": "SUCCESS", "whois_available": True},
    )
    outcomes = build_source_outcomes(InvestigationInput(), entities, [one_domain])
    domain_outcomes = [x for x in outcomes if x.source_name.startswith("domain_dns:") or x.source_name.startswith("domain_whois:")]
    assert len(domain_outcomes) == 4
    assert calculate_coverage(outcomes) == 50


def test_invalid_domain_is_not_retried_when_result_omits_normalized_domain(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    decision = AgentDecision(
        action="CALL_TOOL", selected_tool="domain_intelligence",
        rationale="Check extracted domain", arguments={"domain_or_url": "not a valid domain"},
    )
    step = InvestigationStep(step_number=1, decision=decision, result=ToolExecutionResult(
        tool_name="domain_intelligence", status="FAILED",
        provenance=EvidenceProvenance.UNAVAILABLE,
        data={"requested_input": "not a valid domain"},
    ))
    remaining = agent._required_checks_remaining(
        InvestigationInput(), [], ExtractedEntities(detected_domains=["not a valid domain"]), [step]
    )
    assert not any(name == "domain_intelligence" for name, _, _ in remaining)


def test_invoice_payload_excludes_private_memo_and_recipient_email(monkeypatch):
    monkeypatch.setattr(tools, "_paypal_get", lambda path: {
        "id": "INV-1", "status": "SENT",
        "invoicer": {"email_address": "seller@example.com", "name": {"given_name": "Seller"}},
        "primary_recipients": [{"billing_info": {"email_address": "private-recipient@example.com"}}],
        "detail": {"currency_code": "USD", "memo": "SECRET PRIVATE MEMO", "note": "Visible note"},
        "amount": {"value": "10.00", "currency_code": "USD"},
    })
    result = tools.tool_paypal_invoice("INV-1")
    assert result.status == "SUCCESS"
    assert "private_memo" not in result.data
    assert "recipients" not in result.data
    assert "private-recipient@example.com" not in str(result.data)


def test_model_payload_minimizes_invoice_data():
    result = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"invoice_id": "INV-1", "seller_email": "seller@example.com",
              "private_memo": "SECRET", "recipients": [{"email_address": "private@example.com"}]},
    )
    safe = agent._tool_evidence_for_model(result)
    assert "private_memo" not in str(safe)
    assert "private@example.com" not in str(safe)
    assert safe["data"]["seller_email"] == "seller@example.com"


def test_public_trace_does_not_echo_raw_user_message():
    trace = InvestigationTrace(input_context=InvestigationInput(user_text="VERY_PRIVATE_MESSAGE"))
    public = main._public_trace(trace)
    assert "VERY_PRIVATE_MESSAGE" not in str(public)
    assert public["input_summary"]["has_message"] is True


def test_missing_gemini_key_marks_investigation_failed(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    trace = agent.run_investigation(InvestigationInput(user_text="Check this request"))
    assert trace.status == "FAILED"
    assert trace.error_code == "GEMINI_API_KEY_MISSING"
    assert trace.final_scorecard is not None


def test_historical_tool_is_allowlisted_and_requires_domain_argument():
    parsed = agent._parse_decision({
        "action": "CALL_TOOL", "selected_tool": "historical_pattern_search",
        "rationale": "Check historical patterns", "arguments": {"domain_or_url": "example.com"},
    })
    assert parsed.selected_tool == "historical_pattern_search"


def test_elastic_tool_is_not_applicable_without_configuration(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    result = tools.run_tool("historical_pattern_search", {"domain_or_url": "example.com"})
    assert result.status == "NOT_APPLICABLE"
    assert result.error_code == "ELASTIC_NOT_CONFIGURED"


def test_extracted_invoice_identifier_is_forced_through_paypal_lookup(monkeypatch):
    extracted = ExtractedEntities(
        extracted_identifier="INV-EXTRACTED", identifier_hint="INVOICE"
    )
    remaining = agent._required_checks_remaining(
        InvestigationInput(user_text="Invoice INV-EXTRACTED"),
        [], extracted, [],
    )
    assert remaining[0][0] == "extract_message_context"
    assert any(name == "paypal_invoice" and args.get("invoice_id") == "INV-EXTRACTED"
               for name, args, _ in remaining)


def test_non_streaming_endpoint_reports_missing_gemini_as_service_unavailable(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    response = client.post("/api/v1/investigate", json={"user_text": "Check this request"})
    assert response.status_code == 503
    assert response.json()["status"] == "FAILED"
    assert response.json()["error_code"] == "GEMINI_API_KEY_MISSING"


def test_streaming_endpoint_emits_final_failed_status_without_raw_input(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    response = client.post(
        "/api/v1/investigate/stream",
        json={"user_text": "RAW_PRIVATE_TEXT_DO_NOT_ECHO"},
    )
    assert response.status_code == 200
    assert "investigation_result" in response.text
    assert '"status":"FAILED"' in response.text
    assert "RAW_PRIVATE_TEXT_DO_NOT_ECHO" not in response.text
