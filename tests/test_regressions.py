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
        response = await endpoint(watchtower.DemoEventRequest(identifier="INV-DEMO"))
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
