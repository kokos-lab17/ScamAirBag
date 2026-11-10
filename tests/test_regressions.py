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


def test_tls_observation_records_verified_certificate_metadata(monkeypatch):
    class FakeTLSSocket:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def getpeercert(self):
            return {
                "notBefore": "Jan  1 00:00:00 2025 GMT",
                "notAfter": "Jan  1 00:00:00 2027 GMT",
                "issuer": ((('commonName', 'Test CA'),),),
                "subjectAltName": (("DNS", "example.com"),),
            }
    class FakeRawSocket:
        def close(self): pass
    class FakeContext:
        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "example.com"
            return FakeTLSSocket()
    monkeypatch.setattr(tools.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(tools.socket, "create_connection", lambda address, timeout: FakeRawSocket())
    result = tools._tls_certificate_observation("example.com", ["93.184.216.34"])
    assert result["tls_status"] == "VALID"
    assert result["tls_hostname_verified"] is True
    assert result["tls_subject_alt_names"] == ["example.com"]
    assert result["tls_issuer"] == "commonName=Test CA"


def test_tls_observation_reports_certificate_verification_failure(monkeypatch):
    class FakeRawSocket:
        def close(self): pass
    class FakeContext:
        def wrap_socket(self, raw, server_hostname):
            raise tools.ssl.SSLCertVerificationError("hostname mismatch")
    monkeypatch.setattr(tools.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(tools.socket, "create_connection", lambda address, timeout: FakeRawSocket())
    result = tools._tls_certificate_observation("example.com", ["93.184.216.34"])
    assert result["tls_status"] == "INVALID"
    assert result["tls_error"] == "TLS_CERTIFICATE_VERIFICATION_FAILED"
    assert result["tls_hostname_verified"] is False


def test_redirect_inspection_records_cross_domain_redirects(monkeypatch):
    monkeypatch.setattr(tools, "_resolve_domain", lambda host: ["93.184.216.34"])
    calls = []
    def fake_head(url, domain, ip):
        calls.append((url, domain, ip))
        if domain == "short.example":
            return {"status_code": 302, "location": "https://destination.example/login"}
        return {"status_code": 200, "location": None}
    monkeypatch.setattr(tools, "_head_request_pinned", fake_head)

    result = tools.tool_link_redirect_inspection("https://short.example/a")

    assert result.status == "SUCCESS"
    assert result.data["initial_host"] == "short.example"
    assert result.data["final_host"] == "destination.example"
    assert result.data["cross_domain_redirect"] is True
    assert len(result.data["redirect_hops"]) == 2
    assert len(calls) == 2


def test_redirect_inspection_blocks_private_destination(monkeypatch):
    def fake_resolve(host):
        if host == "short.example":
            return ["93.184.216.34"]
        return ["127.0.0.1"]
    monkeypatch.setattr(tools, "_resolve_domain", fake_resolve)
    monkeypatch.setattr(
        tools, "_head_request_pinned",
        lambda url, domain, ip: {"status_code": 302, "location": "http://internal.example/admin"},
    )

    result = tools.tool_link_redirect_inspection("https://short.example/a")

    assert result.status == "SUCCESS"
    assert result.data["blocked_unsafe_destination"] is True
    assert result.data["redirect_hops"][-1]["status"] == "BLOCKED_NON_PUBLIC_DNS"


def test_redirect_inspection_is_counted_in_evidence_coverage():
    url = "https://short.example/claim"
    entities = ExtractedEntities(detected_urls=[url])
    pending = build_source_outcomes(InvestigationInput(user_text="Check this link"), entities, [])
    pending_redirect = next(x for x in pending if x.source_name.startswith("link_redirect:"))
    assert pending_redirect.status == "SKIPPED"

    completed = ToolExecutionResult(
        tool_name="link_redirect_inspection",
        status="SUCCESS",
        provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
        data={"initial_url": url, "initial_host": "short.example", "final_host": "destination.example"},
    )
    outcomes = build_source_outcomes(InvestigationInput(user_text="Check this link"), entities, [completed])
    checked_redirect = next(x for x in outcomes if x.source_name.startswith("link_redirect:"))
    assert checked_redirect.status == "SUCCESS"
    assert calculate_coverage(outcomes) > calculate_coverage(pending)


def test_link_extraction_detects_malformed_paypal_link():
    result = tools._extract_link_evidence("PayPal link:123hduyen23unfhjc")
    assert result["detected_urls"] == []
    assert result["malformed_urls"] == ["123hduyen23unfhjc"]
    assert result["detected_domains"] == []
    assert "PayPal link:123hduyen23unfhjc" in result["link_context"][0]


def test_link_extraction_detects_complete_url_and_domain():
    result = tools._extract_link_evidence(
        "Please pay here: https://payments.example.com/invoice/123"
    )
    assert result["detected_urls"] == ["https://payments.example.com/invoice/123"]
    assert result["detected_domains"] == ["payments.example.com"]
    assert result["malformed_urls"] == []


def test_duplicate_payment_tactic_is_counted_once():
    from scoring import _build_findings
    entities = ExtractedEntities(
        coercion_tactics=["friends_and_family_diversion"],
        unusual_payment_instructions=["friends_and_family_diversion"],
        raw_evidence_quotes=["use family account"],
    )
    findings, _ = _build_findings(entities, [])
    overlap = [f for f in findings if "friends and family diversion" in f.description]
    assert len(overlap) == 1
    assert overlap[0].rule_id == "UNUSUAL_PAYMENT_INSTRUCTION"
    assert sum(f.risk_impact for f in overlap) == 25


def test_paypal_account_limitation_message_gets_content_risk_findings():
    from scoring import _build_findings

    message = (
        "[PayPal]: Your account access has been limited. "
        "Your PayPal account is limited. You have 24 hours to solve the problem "
        "or your account will be permanently disabled. "
        "You have to confirm all of your account details on our secured server."
    )
    entities = ExtractedEntities()
    findings, _ = _build_findings(entities, [], message)
    rule_ids = {finding.rule_id for finding in findings}

    assert "ARTIFICIAL_DEADLINE" in rule_ids
    assert "ACCOUNT_ACCESS_THREAT" in rule_ids
    assert "SENSITIVE_INFORMATION_REQUEST" in rule_ids
    assert sum(finding.risk_impact for finding in findings) >= 40


def test_paypal_account_limitation_scorecard_is_auditable_and_requires_verification():
    from scoring import score_investigation

    message = (
        "[PayPal]: Your account access has been limited. "
        "Your PayPal account is limited. You have 24 hours to solve the problem "
        "or your account will be permanently disabled. "
        "You have to confirm all of your account details on our secured server."
    )
    scorecard, _ = score_investigation(
        InvestigationInput(user_text=message),
        ExtractedEntities(),
        [],
    )

    assert scorecard.risk_score == 40
    assert scorecard.recommended_action.value == "PROCEED_WITH_MANUAL_VERIFICATION"
    assert scorecard.confidence_level == "LOW"
    assert {finding.rule_id for finding in scorecard.findings} >= {
        "ARTIFICIAL_DEADLINE",
        "ACCOUNT_ACCESS_THREAT",
        "SENSITIVE_INFORMATION_REQUEST",
    }


def test_malformed_link_adds_info_finding_not_risk_points():
    from scoring import _build_findings
    entities = ExtractedEntities(malformed_urls=["123hduyen23unfhjc"])
    findings, _ = _build_findings(entities, [])
    malformed = [f for f in findings if f.rule_id == "MALFORMED_OR_INCOMPLETE_LINK"]
    assert len(malformed) == 1
    assert malformed[0].risk_impact == 0
    assert malformed[0].severity.value == "INFO"


def test_gemini_extraction_falls_back_after_transient_primary_error(monkeypatch):
    calls = []

    class FakeModels:
        def generate_content(self, *, model, contents, config):
            calls.append(model)
            if model == "primary-test":
                error = RuntimeError("temporary unavailable")
                error.code = 503
                raise error
            return {"ok": True}

    class FakeClient:
        models = FakeModels()

    monkeypatch.setattr(tools, "GEMINI_MODEL", "primary-test")
    monkeypatch.setattr(tools, "GEMINI_FALLBACK_MODEL", "fallback-test")
    result = tools._generate_with_model_fallback(
        FakeClient(), contents="test", config=None
    )
    assert result == {"ok": True}
    assert calls == ["primary-test", "fallback-test"]


def test_public_trace_exposes_allowlisted_domain_evidence_only():
    trace = InvestigationTrace(
        input_context=InvestigationInput(user_text="Check https://example.com"),
        steps=[InvestigationStep(
            step_number=1,
            decision=AgentDecision(
                action="CALL_TOOL", selected_tool="domain_intelligence",
                rationale="Check public domain metadata",
                arguments={"domain_or_url": "example.com"},
            ),
            result=ToolExecutionResult(
                tool_name="domain_intelligence", status="SUCCESS",
                provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
                data={
                    "domain": "example.com", "dns_status": "SUCCESS",
                    "resolved_ips": ["93.184.216.34"], "tls_status": "VALID",
                    "tls_hostname_verified": True,
                    "registrant_email": "private@example.com",
                },
            ),
        )],
    )
    public = main._public_trace(trace)
    assert public["domain_evidence"][0]["observations"]["tls_status"] == "VALID"
    assert public["domain_evidence"][0]["observations"]["resolved_ips"] == ["93.184.216.34"]
    assert "registrant_email" not in str(public)

def test_public_trace_does_not_expose_model_rationale():
    trace = InvestigationTrace(
        input_context=InvestigationInput(user_text="Check this request"),
        steps=[InvestigationStep(
            step_number=1,
            decision=AgentDecision(
                action="CALL_TOOL",
                selected_tool="domain_intelligence",
                rationale="Private model text that must not be exposed",
                arguments={"domain_or_url": "example.com"},
            ),
        )],
    )
    public = main._public_trace(trace)
    assert "rationale" not in public["steps"][0]
    assert "Private model text" not in str(public)


def test_lookalike_domain_detector_flags_one_edit_paypal_domain():
    result = tools._lookalike_domain_observation("paypa1.com")
    assert result["status"] == "POTENTIAL_MATCH"
    assert any(
        item["brand_domain"] == "paypal.com"
        and item["match_type"] == "ONE_EDIT_DOMAIN_SIMILARITY"
        for item in result["matches"]
    )
    assert "not proof" in result["disclaimer"]


def test_lookalike_domain_detector_flags_brand_in_deceptive_subdomain():
    result = tools._lookalike_domain_observation("paypal.com.attacker.test")
    assert result["status"] == "POTENTIAL_MATCH"
    assert any(item["match_type"] == "BRAND_NAME_IN_SUBDOMAIN" for item in result["matches"])


def test_lookalike_domain_detector_does_not_flag_exact_canonical_domain():
    result = tools._lookalike_domain_observation("paypal.com")
    assert result["status"] == "NO_MATCH_IN_REFERENCE_SET"
    assert result["matches"] == []


def test_email_authentication_header_parser_extracts_results_and_domains():
    result = tools.inspect_email_authentication_headers(
        "From: Billing <alerts@paypal.com>\n"
        "Return-Path: <bounce@mailer.example>\n"
        "Authentication-Results: mx.example; spf=pass smtp.mailfrom=mailer.example; "
        "dkim=pass header.d=paypal.com; dmarc=fail header.from=paypal.com\n"
        "DKIM-Signature: v=1; d=paypal.com; s=mail; b=abc\n\nBody ignored"
    )
    assert result.status == "SUCCESS"
    assert result.data["from_domain"] == "paypal.com"
    assert result.data["return_path_domain"] == "mailer.example"
    methods = result.data["authentication_results"][0]["methods"]
    assert { (item["method"], item["result"]) for item in methods } == {
        ("spf", "pass"), ("dkim", "pass"), ("dmarc", "fail")
    }
    assert result.data["dkim_signing_domains"] == ["paypal.com"]
    assert "does not prove" in " ".join(result.data["limitations"])


def test_email_authentication_header_parser_does_not_treat_missing_auth_results_as_pass():
    result = tools.inspect_email_authentication_headers(
        "From: User <user@example.com>\nSubject: Test\n"
    )
    assert result.status == "SUCCESS"
    assert result.data["authentication_results"] == []
    assert result.data["received_spf_results"] == []


def test_email_headers_are_optional_but_valid_input():
    request = main.InvestigationRequest(email_headers="From: user@example.com")
    assert request.email_headers == "From: user@example.com"
    assert request.to_investigation_input().email_headers == "From: user@example.com"


def test_email_authentication_coverage_is_not_applicable_without_headers():
    outcomes = build_source_outcomes(InvestigationInput(user_text="hello"), None, [])
    email = next(item for item in outcomes if item.source_name == "email_authentication")
    assert email.applicable is False
    assert email.status == "NOT_APPLICABLE"


def test_watchtower_demo_event_schedules_investigation_and_persists(tmp_path, monkeypatch):
    import asyncio
    import watchtower
    from schemas import InvestigationTrace, AirbagScorecard, RecommendedAction

    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_DEMO_ENABLED", True)
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "test-watchtower-token")
    monkeypatch.setattr(watchtower, "run_investigation", lambda payload: InvestigationTrace(
        input_context=payload, status="COMPLETED",
        final_scorecard=AirbagScorecard(
            risk_score=12, coverage_score=100, confidence_level="HIGH",
            recommended_action=RecommendedAction.PROCEED_WITH_MANUAL_VERIFICATION,
            executive_summary="Test only", findings=[]
        )
    ))
    router = watchtower.build_watchtower_router(lambda trace: {
        "status": trace.status,
        "final_scorecard": trace.final_scorecard.model_dump(mode="json")
    })
    endpoint = next(route.endpoint for route in router.routes
                    if getattr(route, "path", "") == "/api/v1/watchtower/demo/simulate-invoice")

    async def scenario():
        response = await endpoint(watchtower.DemoEventRequest(identifier="INV-DEMO"), x_watchtower_token="test-watchtower-token")
        assert response["accepted"] is True
        event_id = response["event"]["event_id"]
        for _ in range(30):
            await asyncio.sleep(0.02)
            with watchtower._connect() as db:
                row = db.execute("SELECT status, result_json FROM watchtower_events WHERE event_id=?", (event_id,)).fetchone()
            if row["status"] in {"COMPLETED", "FAILED", "PARTIAL"}:
                break
        assert row["status"] == "COMPLETED"
        assert row["result_json"] is not None

    asyncio.run(scenario())


def test_watchtower_ingest_requires_configured_shared_secret(monkeypatch):
    import watchtower
    from fastapi import HTTPException
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "expected-secret")
    with pytest.raises(HTTPException) as exc:
        watchtower._require_ingest_token("wrong-secret")
    assert exc.value.status_code == 401


def test_watchtower_requires_secret_even_when_not_configured(monkeypatch):
    import watchtower
    from fastapi import HTTPException
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "")
    with pytest.raises(HTTPException) as exc:
        watchtower._require_ingest_token(None)
    assert exc.value.status_code == 401


def test_watchtower_paypal_signature_verification_uses_paypal_verify_api(monkeypatch):
    import watchtower

    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "WH-TEST")
    monkeypatch.setattr(watchtower, "_get_paypal_access_token", lambda: "oauth-token")
    monkeypatch.setattr(watchtower, "PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    captured = {}
    class Response:
        def raise_for_status(self): pass
        def json(self): return {"verification_status": "SUCCESS"}
    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()
    monkeypatch.setattr(watchtower.requests, "post", fake_post)
    raw = b'{"id":"WH-EVENT-1","event_type":"INVOICING.INVOICE.SENT","resource":{"id":"INV-1"}}'
    verified = watchtower._verify_paypal_signature({
        "paypal-transmission-id": "tx-1",
        "paypal-transmission-time": "2026-11-10T10:00:00Z",
        "paypal-cert-url": "https://api.paypal.com/cert",
        "paypal-auth-algo": "SHA256withRSA",
        "paypal-transmission-sig": "signature",
    }, {"id": "WH-EVENT-1", "event_type": "INVOICING.INVOICE.SENT", "resource": {"id": "INV-1"}}, raw)

    assert verified is True
    assert captured["url"].endswith("/v1/notifications/verify-webhook-signature")
    assert captured["headers"]["Authorization"] == "Bearer oauth-token"
    assert captured["data"].endswith(b',"webhook_event":' + raw + b'}')
    assert b'"webhook_id":"WH-TEST"' in captured["data"]


def test_watchtower_event_creation_is_idempotent(tmp_path, monkeypatch):
    import watchtower
    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    watchtower.init_watchtower()
    first, duplicate_first = watchtower._create_event("event-1", "TEST", "INVOICE.CREATED", "INV-1", "INVOICE")
    second, duplicate_second = watchtower._create_event("event-1", "TEST", "INVOICE.CREATED", "INV-1", "INVOICE")
    assert duplicate_first is False
    assert duplicate_second is True
    assert first["event_id"] == second["event_id"]


def test_watchtower_startup_recovers_interrupted_jobs(tmp_path, monkeypatch):
    import asyncio
    import watchtower
    from schemas import InvestigationTrace, AirbagScorecard, RecommendedAction

    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    watchtower.init_watchtower()
    record, duplicate = watchtower._create_event("restart-event", "TEST", "INVOICE.CREATED", "INV-2", "INVOICE")
    assert duplicate is False
    with watchtower._db() as db:
        db.execute("UPDATE watchtower_events SET status='INVESTIGATING' WHERE event_id='restart-event'")
    monkeypatch.setattr(watchtower, "run_investigation", lambda payload: InvestigationTrace(
        input_context=payload, status="COMPLETED",
        final_scorecard=AirbagScorecard(
            risk_score=5, coverage_score=100, confidence_level="HIGH",
            recommended_action=RecommendedAction.PROCEED_WITH_MANUAL_VERIFICATION,
            executive_summary="Test", findings=[]
        )
    ))

    async def scenario():
        await watchtower.resume_watchtower_jobs(lambda trace: {"status": trace.status})
        for _ in range(30):
            await asyncio.sleep(0.02)
            with watchtower._db() as db:
                row = db.execute("SELECT status FROM watchtower_events WHERE event_id='restart-event'").fetchone()
            if row["status"] == "COMPLETED":
                break
        assert row["status"] == "COMPLETED"

    asyncio.run(scenario())


def test_watchtower_invoice_investigation_requires_seller_email_domain_check(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"invoice_id": "INV-1", "seller_email": "billing@merchant-example.test"},
    )
    remaining = agent._required_checks_remaining(InvestigationInput(), [invoice], None, [])
    assert remaining[0][0] == "domain_intelligence"
    assert remaining[0][1]["domain_or_url"] == "merchant-example.test"


def test_subscription_payer_email_is_not_mistaken_for_seller_domain(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    subscription = ToolExecutionResult(
        tool_name="paypal_subscription", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"subscription_id": "SUB-1", "subscriber_email": "payer@example.test"},
    )
    remaining = agent._required_checks_remaining(InvestigationInput(), [subscription], None, [])
    assert not any(name == "domain_intelligence" for name, _, _ in remaining)


def test_watchtower_alert_policy_flags_high_risk_and_incomplete_results():
    from watchtower import _build_watchtower_alert
    from schemas import AirbagScorecard, RecommendedAction, InvestigationTrace, InvestigationInput

    high = InvestigationTrace(
        input_context=InvestigationInput(identifier="INV-1", identifier_hint="INVOICE"),
        status="COMPLETED",
        final_scorecard=AirbagScorecard(
            risk_score=76, coverage_score=90, confidence_level="HIGH",
            recommended_action=RecommendedAction.ABORT_PAYMENT,
            executive_summary="Test", findings=[]
        )
    )
    alert = _build_watchtower_alert(high)
    assert alert["level"] == "CRITICAL"
    assert alert["needs_attention"] is True
    assert alert["recommended_action"] == "ABORT_PAYMENT"

    partial = InvestigationTrace(
        input_context=InvestigationInput(identifier="INV-2", identifier_hint="INVOICE"),
        status="PARTIAL",
    )
    partial_alert = _build_watchtower_alert(partial)
    assert partial_alert["level"] == "INCOMPLETE"
    assert partial_alert["needs_attention"] is True


def test_coverage_tracks_verified_paypal_seller_domain_without_message_text():
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"invoice_id": "INV-2", "seller_email": "billing@merchant-example.test"},
    )
    domain = ToolExecutionResult(
        tool_name="domain_intelligence", status="SUCCESS",
        provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
        data={"domain": "merchant-example.test", "dns_status": "SUCCESS",
              "whois_status": "SUCCESS", "whois_available": True},
    )
    outcomes = build_source_outcomes(InvestigationInput(), None, [invoice, domain])
    names = {item.source_name for item in outcomes}
    assert "domain_dns:merchant-example.test" in names
    assert "domain_whois:merchant-example.test" in names


def test_coverage_does_not_treat_subscription_payer_as_seller_domain():
    subscription = ToolExecutionResult(
        tool_name="paypal_subscription", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"subscription_id": "SUB-2", "subscriber_email": "payer@example.test"},
    )
    outcomes = build_source_outcomes(InvestigationInput(), None, [subscription])
    assert not any(item.source_name == "domain_dns:example.test" for item in outcomes)


def test_watchtower_event_history_requires_access_token(tmp_path, monkeypatch):
    import asyncio
    import watchtower
    from fastapi import HTTPException

    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "private-token")
    router = watchtower.build_watchtower_router(lambda trace: {})
    endpoint = next(route.endpoint for route in router.routes
                    if getattr(route, "path", "") == "/api/v1/watchtower/events")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(endpoint(limit=20, x_watchtower_token=None))
    assert exc.value.status_code == 401


def test_watchtower_demo_trigger_requires_access_token(tmp_path, monkeypatch):
    import asyncio
    import watchtower
    from fastapi import HTTPException

    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "private-token")
    monkeypatch.setattr(watchtower, "_DEMO_ENABLED", True)
    router = watchtower.build_watchtower_router(lambda trace: {})
    endpoint = next(route.endpoint for route in router.routes
                    if getattr(route, "path", "") == "/api/v1/watchtower/demo/simulate-invoice")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(endpoint(watchtower.DemoEventRequest(identifier="INV-1"), x_watchtower_token=None))
    assert exc.value.status_code == 401


def test_watchtower_registers_paypal_webhook_and_persists_id(tmp_path, monkeypatch):
    import asyncio
    import watchtower

    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "private-token")
    monkeypatch.setattr(watchtower, "_get_paypal_access_token", lambda: "oauth-token")
    monkeypatch.setattr(watchtower, "PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    monkeypatch.setenv("WATCHTOWER_PUBLIC_API_URL", "https://scamairbag.example")
    monkeypatch.delenv("PAYPAL_WEBHOOK_ID", raising=False)
    captured = {}
    class Response:
        def raise_for_status(self): pass
        def json(self): return {"id": "WH-REGISTERED"}
    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()
    monkeypatch.setattr(watchtower.requests, "post", fake_post)

    router = watchtower.build_watchtower_router(lambda trace: {})
    endpoint = next(route.endpoint for route in router.routes
                    if getattr(route, "path", "") == "/api/v1/watchtower/paypal/register")
    result = asyncio.run(endpoint(x_watchtower_token="private-token"))
    assert result["registered"] is True
    assert result["webhook_id"] == "WH-REGISTERED"
    assert captured["url"].endswith("/v1/notifications/webhooks")
    assert captured["json"]["url"] == "https://scamairbag.example/api/v1/watchtower/paypal/webhook"
    assert "CHECKOUT.ORDER.APPROVED" in [item["name"] for item in captured["json"]["event_types"]]
    assert watchtower._get_setting("PAYPAL_WEBHOOK_ID") == "WH-REGISTERED"


def test_raw_email_headers_are_not_included_in_model_context():
    from agent import _model_input_context

    request = InvestigationInput(
        user_text="Please check this payment request.",
        email_headers="From: private-sender@example.com\\nAuthentication-Results: private-auth-value",
    )
    model_context = _model_input_context(request)
    assert model_context["user_text"] == "Please check this payment request."
    assert "private-sender@example.com" not in str(model_context)
    assert "private-auth-value" not in str(model_context)
    assert "PARSED LOCALLY" in model_context["email_headers"]


def test_evidence_manifest_hashes_and_detects_tampering():
    from evidence_manifest import build_evidence_manifest, verify_evidence_manifest

    trace = InvestigationTrace(
        input_context=InvestigationInput(user_text="Invoice INV-123"),
        steps=[InvestigationStep(
            step_number=1,
            decision=AgentDecision(action="CALL_TOOL", selected_tool="paypal_invoice",
                                   rationale="Verify invoice", arguments={"invoice_id": "INV-123"}),
            result=ToolExecutionResult(
                tool_name="paypal_invoice", status="SUCCESS",
                provenance=EvidenceProvenance.VERIFIED_PAYPAL,
                data={"invoice_id": "INV-123", "status": "SENT",
                      "seller_email": "seller@example.com",
                      "private_memo": "MUST NOT BE IN MANIFEST",
                      "amount": {"value": "100.00", "currency_code": "USD"}},
            ),
        )],
    )
    manifest = build_evidence_manifest(trace)
    assert verify_evidence_manifest(manifest)["valid"] is True
    assert "MUST NOT BE IN MANIFEST" not in str(manifest)
    manifest["evidence_records"][0]["evidence"]["status"] = "PAID"
    verified = verify_evidence_manifest(manifest)
    assert verified["valid"] is False
    assert any("hash mismatch" in error for error in verified["errors"])


def test_evidence_manifest_is_in_public_investigation_response():
    trace = InvestigationTrace(input_context=InvestigationInput(user_text="Check this invoice"))
    public = main._public_trace(trace)
    assert public["evidence_manifest"]["manifest_version"] == "1.0"
    assert len(public["evidence_manifest"]["root_sha256"]) == 64
    assert "not a digital signature" in public["evidence_manifest"]["integrity_note"]


def test_evidence_manifest_verification_endpoint_accepts_valid_manifest():
    from fastapi.testclient import TestClient
    from evidence_manifest import build_evidence_manifest

    manifest = build_evidence_manifest(
        InvestigationTrace(input_context=InvestigationInput(user_text="test"))
    )
    response = TestClient(main.app).post("/api/v1/evidence/verify", json={"manifest": manifest})
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_claimed_amount_mismatch_against_verified_invoice_is_scored():
    from scoring import score_investigation

    entities = ExtractedEntities(
        claimed_amount="125.00", claimed_currency_code="USD",
        claimed_amount_quote="Pay USD 125.00 today",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "USD"}},
    )
    scorecard, _ = score_investigation(
        InvestigationInput(user_text="Please Pay USD 125.00 today"),
        entities, [invoice],
    )
    mismatch = next(item for item in scorecard.findings if item.rule_id == "PAYMENT_AMOUNT_MISMATCH")
    assert mismatch.risk_impact == 40
    assert mismatch.provenance == EvidenceProvenance.VERIFIED_PAYPAL


def test_claimed_amount_is_not_compared_without_exact_supporting_quote():
    from scoring import score_investigation

    entities = ExtractedEntities(
        claimed_amount="125.00", claimed_currency_code="USD",
        claimed_amount_quote="Pay USD 125.00 today",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "USD"}},
    )
    scorecard, _ = score_investigation(
        InvestigationInput(user_text="Pay USD 999.00 today"),
        entities, [invoice],
    )
    assert not any(item.rule_id == "PAYMENT_AMOUNT_MISMATCH" for item in scorecard.findings)
    assert any("verbatim supporting quote" in item for item in scorecard.unverified_claims)


def test_claimed_amount_currency_must_match_before_comparison():
    from scoring import _compare_claimed_amount

    entities = ExtractedEntities(
        claimed_amount="100", claimed_currency_code="EUR",
        claimed_amount_quote="Pay EUR 100",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "USD"}},
    )
    match, reason = _compare_claimed_amount(entities, [invoice], "Pay EUR 100")
    assert match is None
    assert "No verified PayPal invoice/order amount in EUR" in reason


def test_lookalike_domain_generates_explainable_caution_finding():
    from scoring import _build_findings

    result = ToolExecutionResult(
        tool_name="domain_intelligence", status="SUCCESS",
        provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
        data={"domain": "paypa1.com", "lookalike_observation": tools._lookalike_domain_observation("paypa1.com")},
    )
    findings, _ = _build_findings(None, [result])
    finding = next(item for item in findings if item.rule_id == "POTENTIAL_BRAND_LOOKALIKE")
    assert finding.risk_impact == 20
    assert "not proof" in finding.description


def test_https_downgrade_and_cross_domain_redirect_are_scored_separately():
    from scoring import _build_findings

    result = ToolExecutionResult(
        tool_name="link_redirect_inspection", status="SUCCESS",
        provenance=EvidenceProvenance.OBSERVED_EXTERNAL,
        data={"initial_host": "short.example", "final_host": "destination.example",
              "cross_domain_redirect": True, "https_downgrade": True,
              "redirect_hops": [{"host": "short.example", "status_code": 302}]},
    )
    findings, _ = _build_findings(None, [result])
    rules = {item.rule_id for item in findings}
    assert "HTTPS_TO_HTTP_DOWNGRADE" in rules
    assert "CROSS_DOMAIN_REDIRECT" in rules


def test_pasted_email_authentication_failure_is_not_misrepresented_as_verified():
    from scoring import _build_findings

    result = ToolExecutionResult(
        tool_name="email_authentication_headers", status="SUCCESS",
        provenance=EvidenceProvenance.USER_PROVIDED,
        data={"authentication_results": [{"methods": [{"method": "dmarc", "result": "fail"}]}]},
    )
    findings, _ = _build_findings(None, [result])
    finding = next(item for item in findings if item.rule_id == "EMAIL_AUTHENTICATION_FAILURE_CLAIM")
    assert finding.provenance == EvidenceProvenance.USER_PROVIDED
    assert finding.risk_impact == 10


def test_agent_rejects_model_invented_external_domains():
    assert not agent._tool_target_is_grounded(
        "domain_intelligence", {"domain_or_url": "attacker.example"},
        InvestigationInput(user_text="Please check https://paypal.com/login"), [],
    )
    assert agent._tool_target_is_grounded(
        "domain_intelligence", {"domain_or_url": "paypal.com"},
        InvestigationInput(user_text="Please check https://paypal.com/login"), [],
    )


def test_agent_only_inspects_exact_user_supplied_redirect_urls():
    request = InvestigationInput(user_text="Open https://short.example/path")
    assert agent._tool_target_is_grounded(
        "link_redirect_inspection", {"url": "https://short.example/path"}, request, []
    )
    assert not agent._tool_target_is_grounded(
        "link_redirect_inspection", {"url": "https://attacker.example/path"}, request, []
    )


def test_agent_can_inspect_domain_returned_by_verified_paypal_seller():
    paypal = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"seller_email": "merchant@verified-seller.example"},
    )
    assert agent._tool_target_is_grounded(
        "domain_intelligence", {"domain_or_url": "verified-seller.example"},
        InvestigationInput(identifier="INV-1", identifier_hint="INVOICE"), [paypal],
    )


def test_evidence_manifest_metadata_is_covered_by_root_hash():
    from evidence_manifest import build_evidence_manifest, verify_evidence_manifest

    manifest = build_evidence_manifest(
        InvestigationTrace(input_context=InvestigationInput(user_text="test"))
    )
    manifest["created_at"] = "2000-01-01T00:00:00+00:00"
    assert verify_evidence_manifest(manifest)["valid"] is False


def test_production_investigation_requires_service_token(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setenv("WATCHTOWER_INGEST_TOKEN", "production-test-token")
    monkeypatch.delenv("SCAM_AIRBAG_API_TOKEN", raising=False)
    client = TestClient(main.app)
    denied = client.post("/api/v1/investigate", json={"user_text": "test"})
    assert denied.status_code == 401
    allowed = client.post(
        "/api/v1/investigate", json={"user_text": "test"},
        headers={"X-Watchtower-Token": "production-test-token"},
    )
    # The request passes the auth middleware and reaches normal validation/runtime.
    assert allowed.status_code != 401


def test_production_investigation_fails_closed_without_configured_token(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.delenv("WATCHTOWER_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("SCAM_AIRBAG_API_TOKEN", raising=False)
    response = TestClient(main.app).post(
        "/api/v1/investigate", json={"user_text": "test"}
    )
    assert response.status_code == 503
    assert "not been configured" in response.json()["detail"]


def test_direct_verified_paypal_lookup_is_preserved_when_gemini_is_unavailable(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(agent, "run_tool", lambda name, args: ToolExecutionResult(
        tool_name=name, status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"invoice_id": args.get("invoice_id"), "status": "SENT",
              "amount": {"value": "10.00", "currency_code": "USD"}},
    ))
    trace = agent.run_investigation(
        InvestigationInput(identifier="INV-123", identifier_hint="INVOICE")
    )
    assert trace.status == "PARTIAL"
    assert trace.error_code == "GEMINI_API_KEY_MISSING"
    assert trace.final_scorecard is not None
    assert any(item.source_name == "paypal_invoice" and item.status == "SUCCESS"
               for item in trace.source_outcomes)


def test_production_investigation_rate_limit_is_enforced(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setattr(main, "INVESTIGATION_RATE_LIMIT_PER_MINUTE", 1)
    main._rate_windows.clear()
    monkeypatch.setenv("WATCHTOWER_INGEST_TOKEN", "rate-test-token")
    monkeypatch.delenv("SCAM_AIRBAG_API_TOKEN", raising=False)
    client = TestClient(main.app)
    headers = {"X-Watchtower-Token": "rate-test-token"}
    first = client.post("/api/v1/investigate", json={"user_text": "first"}, headers=headers)
    second = client.post("/api/v1/investigate", json={"user_text": "second"}, headers=headers)
    assert first.status_code != 401
    assert second.status_code == 429
    assert second.headers["Retry-After"]


def test_production_investigation_rejects_oversized_body(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setenv("WATCHTOWER_INGEST_TOKEN", "size-test-token")
    monkeypatch.delenv("SCAM_AIRBAG_API_TOKEN", raising=False)
    response = TestClient(main.app).post(
        "/api/v1/investigate",
        content='{"user_text":"' + ("x" * 41000) + '"}',
        headers={"Content-Type": "application/json", "X-Watchtower-Token": "size-test-token"},
    )
    assert response.status_code == 413


def test_paypal_subscription_includes_verified_recurring_plan_price(monkeypatch):
    def fake_get(path):
        if path.endswith("/subscriptions/I-SUB-123"):
            return {
                "id": "I-SUB-123", "status": "ACTIVE", "plan_id": "P-PLAN-123",
                "subscriber": {"email_address": "payer@example.com"},
                "billing_info": {"next_billing_time": "2027-01-01T00:00:00Z",
                                 "failed_payments_count": 0},
            }
        assert path.endswith("/plans/P-PLAN-123")
        return {
            "id": "P-PLAN-123", "name": "Monthly service", "status": "ACTIVE",
            "billing_cycles": [{
                "tenure_type": "REGULAR", "sequence": 1, "total_cycles": 0,
                "frequency": {"interval_unit": "MONTH", "interval_count": 1},
                "pricing_scheme": {"fixed_price": {"value": "19.99", "currency_code": "USD"}},
            }],
        }
    monkeypatch.setattr(tools, "_paypal_get", fake_get)
    result = tools.tool_paypal_subscription("I-SUB-123")
    assert result.status == "SUCCESS"
    assert result.provenance == EvidenceProvenance.VERIFIED_PAYPAL
    assert result.data["plan_name"] == "Monthly service"
    assert result.data["billing_cycles"][0]["price_value"] == "19.99"
    assert result.data["billing_cycles"][0]["currency_code"] == "USD"
    assert result.data["next_billing_time"] == "2027-01-01T00:00:00Z"


def test_public_trace_exposes_minimized_paypal_plan_evidence_not_private_payer_email():
    trace = InvestigationTrace(
        input_context=InvestigationInput(identifier="I-SUB-123", identifier_hint="SUBSCRIPTION"),
        steps=[InvestigationStep(
            step_number=1,
            decision=AgentDecision(action="CALL_TOOL", selected_tool="paypal_subscription",
                                   rationale="Verify recurring plan", arguments={"subscription_id": "I-SUB-123"}),
            result=ToolExecutionResult(
                tool_name="paypal_subscription", status="SUCCESS",
                provenance=EvidenceProvenance.VERIFIED_PAYPAL,
                data={"subscription_id": "I-SUB-123", "plan_name": "Monthly service",
                      "billing_cycles": [{"price_value": "19.99", "currency_code": "USD"}],
                      "subscriber_email": "private-payer@example.com"},
            ),
        )],
    )
    public = main._public_trace(trace)
    assert public["paypal_evidence"][0]["evidence"]["plan_name"] == "Monthly service"
    assert "private-payer@example.com" not in str(public)


def test_subscription_plan_pricing_is_a_separate_applicable_coverage_check():
    subscription = ToolExecutionResult(
        tool_name="paypal_subscription", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"subscription_id": "I-SUB-123", "status": "ACTIVE",
              "plan_details_status": "UNAVAILABLE", "plan_error_code": "PAYPAL_HTTP_403"},
    )
    outcomes = build_source_outcomes(
        InvestigationInput(identifier="I-SUB-123", identifier_hint="SUBSCRIPTION"),
        None, [subscription],
    )
    plan = next(item for item in outcomes if item.source_name == "paypal_subscription_plan")
    assert plan.applicable is True
    assert plan.status == "FAILED"
    assert plan.error_code == "PAYPAL_HTTP_403"


def test_amount_comparison_rejects_quote_with_different_numeric_value():
    from scoring import _compare_claimed_amount

    entities = ExtractedEntities(
        claimed_amount="125.00", claimed_currency_code="USD",
        claimed_amount_quote="pay USD 100.00 today",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "USD"}},
    )
    match, reason = _compare_claimed_amount(entities, [invoice], "Please pay USD 100.00 today")
    assert match is None
    assert "does not match" in reason


def test_amount_comparison_does_not_guess_currency_from_dollar_symbol():
    from scoring import _compare_claimed_amount

    entities = ExtractedEntities(
        claimed_amount="100.00", claimed_currency_code="USD",
        claimed_amount_quote="pay $100.00 today",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "USD"}},
    )
    match, reason = _compare_claimed_amount(entities, [invoice], "Please pay $100.00 today")
    assert match is None
    assert "does not establish" in reason


def test_amount_comparison_accepts_unambiguous_rupee_symbol():
    from scoring import _compare_claimed_amount

    entities = ExtractedEntities(
        claimed_amount="100.00", claimed_currency_code="INR",
        claimed_amount_quote="pay ₹100.00 today",
    )
    invoice = ToolExecutionResult(
        tool_name="paypal_invoice", status="SUCCESS",
        provenance=EvidenceProvenance.VERIFIED_PAYPAL,
        data={"amount": {"value": "100.00", "currency_code": "INR"}},
    )
    match, _ = _compare_claimed_amount(entities, [invoice], "Please pay ₹100.00 today")
    assert match is True


def test_evidence_manifest_server_hmac_signature_detects_recomputed_tampering():
    from evidence_manifest import build_evidence_manifest, verify_evidence_manifest

    trace = InvestigationTrace(input_context=InvestigationInput(user_text="Check invoice"))
    manifest = build_evidence_manifest(trace, signing_key="server-signing-secret")
    verified = verify_evidence_manifest(manifest, signing_key="server-signing-secret")
    assert verified["valid"] is True
    assert verified["signature_status"] == "VERIFIED"

    # An attacker can recompute plain SHA-256 fields but cannot forge the server HMAC.
    manifest["evidence_records"].append({
        "evidence_id": "EV-999", "tool_name": "paypal_invoice",
        "status": "SUCCESS", "provenance": "VERIFIED_PAYPAL",
        "error_code": None, "evidence": {"status": "PAID"},
        "sha256": "0" * 64,
    })
    from evidence_manifest import sha256_json
    record = manifest["evidence_records"][-1]
    record["sha256"] = sha256_json({
        key: value for key, value in record.items() if key not in {"evidence_id", "sha256"}
    })
    # Update the root without the signing key: the HMAC must still fail.
    root_payload = {
        "manifest_version": manifest["manifest_version"],
        "created_at": manifest["created_at"],
        "investigation_status": manifest["investigation_status"],
        "integrity_note": manifest["integrity_note"],
        "evidence_records": [item["sha256"] for item in manifest["evidence_records"]],
        "findings": [item["sha256"] for item in manifest["findings"]],
    }
    manifest["root_sha256"] = sha256_json(root_payload)
    rejected = verify_evidence_manifest(manifest, signing_key="server-signing-secret")
    assert rejected["valid"] is False
    assert rejected["signature_status"] == "INVALID"


def test_signed_manifest_cannot_be_verified_without_server_key():
    from evidence_manifest import build_evidence_manifest, verify_evidence_manifest

    manifest = build_evidence_manifest(
        InvestigationTrace(input_context=InvestigationInput(user_text="test")),
        signing_key="private-key",
    )
    result = verify_evidence_manifest(manifest)
    assert result["valid"] is False
    assert result["signature_status"] == "UNVERIFIABLE"


def test_readiness_reports_missing_production_dependencies_without_secrets(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    for key in ("GEMINI_API_KEY", "PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET",
                "SCAM_AIRBAG_API_TOKEN", "WATCHTOWER_INGEST_TOKEN", "EVIDENCE_SIGNING_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WATCHTOWER_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    response = TestClient(main.app).get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["gemini_configured"] is False
    assert "secret" not in str(response.json()).lower()


def test_readiness_reports_configured_service_without_leaking_secret_values(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-secret")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-paypal-client")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-paypal-secret")
    monkeypatch.setenv("SCAM_AIRBAG_API_TOKEN", "test-service-token")
    monkeypatch.setenv("WATCHTOWER_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    response = TestClient(main.app).get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert "test-gemini-secret" not in response.text
    assert "test-paypal-secret" not in response.text


def test_agent_rejects_duplicate_evidence_requests_but_allows_new_targets():
    first = InvestigationStep(
        step_number=1,
        decision=AgentDecision(
            action="CALL_TOOL", selected_tool="domain_intelligence",
            rationale="Check the submitted domain", arguments={"domain_or_url": "https://example.com/path"},
        ),
        result=ToolExecutionResult(
            tool_name="domain_intelligence", status="FAILED",
            provenance=EvidenceProvenance.UNAVAILABLE,
        ),
    )
    assert agent._tool_call_already_attempted(
        "domain_intelligence", {"domain_or_url": "example.com"}, [first]
    )
    assert not agent._tool_call_already_attempted(
        "domain_intelligence", {"domain_or_url": "different.example"}, [first]
    )


def test_agent_stops_cleanly_when_client_disconnects_before_work_starts(monkeypatch):
    import threading

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    cancel = threading.Event()
    cancel.set()
    trace = agent.run_investigation(
        InvestigationInput(user_text="Please inspect this request"),
        cancel_event=cancel,
    )
    assert trace.status == "PARTIAL"
    assert trace.error_code == "CLIENT_DISCONNECTED"
    assert trace.steps == []
    assert trace.final_scorecard is not None


def test_production_cors_preflight_is_not_blocked_by_service_token_middleware(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.delenv("SCAM_AIRBAG_API_TOKEN", raising=False)
    monkeypatch.delenv("WATCHTOWER_INGEST_TOKEN", raising=False)
    response = TestClient(main.app).options(
        "/api/v1/investigate/stream",
        headers={
            "Origin": "https://scamairbag-web-sqh8.onrender.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-watchtower-token",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://scamairbag-web-sqh8.onrender.com"
