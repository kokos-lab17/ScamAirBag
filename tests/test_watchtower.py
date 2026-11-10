"""Watchtower API authentication, idempotency, and storage regressions."""
from fastapi.testclient import TestClient

import main
import watchtower


def _client(monkeypatch, tmp_path):
    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "test-watchtower-token")
    monkeypatch.setattr(watchtower, "_schedule", lambda event_id, public_trace: None)
    # The router creates its schema during import; initialize again after
    # redirecting the database path so each test uses an isolated SQLite file.
    watchtower.init_watchtower()
    return TestClient(main.app)


def test_watchtower_status_is_public_but_event_history_requires_token(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)

    status = client.get("/api/v1/watchtower/status")
    assert status.status_code == 200
    assert status.json()["service"] == "watchtower"

    unauthorized = client.get("/api/v1/watchtower/events?limit=20")
    assert unauthorized.status_code == 401

    wrong_token = client.get(
        "/api/v1/watchtower/events?limit=20",
        headers={"X-Watchtower-Token": "wrong-token"},
    )
    assert wrong_token.status_code == 401

    authorized = client.get(
        "/api/v1/watchtower/events?limit=20",
        headers={"X-Watchtower-Token": "test-watchtower-token"},
    )
    assert authorized.status_code == 200
    assert authorized.json()["events"] == []


def test_watchtower_ingest_is_authenticated_and_idempotent(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    payload = {
        "event_id": "paypal-event-123",
        "event_type": "INVOICING.INVOICE.SENT",
        "identifier": "INV2-TEST",
        "identifier_hint": "INVOICE",
    }

    denied = client.post("/api/v1/watchtower/events", json=payload)
    assert denied.status_code == 401

    headers = {"X-Watchtower-Token": "test-watchtower-token"}
    accepted = client.post("/api/v1/watchtower/events", json=payload, headers=headers)
    assert accepted.status_code == 202
    assert accepted.json()["accepted"] is True
    assert accepted.json()["duplicate"] is False

    duplicate = client.post("/api/v1/watchtower/events", json=payload, headers=headers)
    assert duplicate.status_code == 202
    assert duplicate.json()["duplicate"] is True

    history = client.get("/api/v1/watchtower/events", headers=headers)
    assert history.status_code == 200
    assert len(history.json()["events"]) == 1


def test_redirect_tool_contract_accepts_url_argument():
    from agent import _parse_decision

    decision = _parse_decision({
        "action": "CALL_TOOL",
        "selected_tool": "link_redirect_inspection",
        "rationale": "Inspect the submitted link redirect chain.",
        "arguments": {"url": "https://example.com/pay"},
    })
    assert decision.selected_tool == "link_redirect_inspection"
    assert decision.arguments["url"] == "https://example.com/pay"


def test_watchtower_correlates_recurring_domains_without_calling_them_fraud(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    first_id = "event-first"
    second_id = "event-second"
    first_result = {
        "domain_evidence": [{
            "observations": {"domain": "seller-example.test"},
            "provenance": "OBSERVED_EXTERNAL",
        }]
    }
    watchtower._create_event(first_id, "TEST", "INVOICE", "INV-FIRST", "INVOICE")
    watchtower._update(first_id, status="COMPLETED", result_json=__import__("json").dumps(first_result))
    current = {
        "domain_evidence": [{
            "observations": {"domain": "seller-example.test"},
            "provenance": "OBSERVED_EXTERNAL",
        }]
    }
    correlations = watchtower._correlate_prior_domains(second_id, current)
    assert correlations[0]["domain"] == "seller-example.test"
    assert correlations[0]["prior_case_observations"] == 1
    assert "does not establish" in correlations[0]["interpretation"]


def test_watchtower_includes_recurring_subscription_lifecycle_events():
    expected = {
        "BILLING.SUBSCRIPTION.CREATED",
        "BILLING.SUBSCRIPTION.ACTIVATED",
        "BILLING.SUBSCRIPTION.UPDATED",
        "BILLING.SUBSCRIPTION.SUSPENDED",
        "BILLING.SUBSCRIPTION.CANCELLED",
        "BILLING.SUBSCRIPTION.EXPIRED",
    }
    assert expected.issubset(watchtower.PAYPAL_EVENT_HINTS)
    assert all(watchtower.PAYPAL_EVENT_HINTS[name] == "SUBSCRIPTION" for name in expected)


def test_watchtower_purges_events_outside_retention_window(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    watchtower._create_event("expired-event", "TEST", "INVOICE", "INV-OLD", "INVOICE")
    with watchtower._db() as db:
        db.execute(
            "UPDATE watchtower_events SET received_at=? WHERE event_id=?",
            ("2000-01-01T00:00:00+00:00", "expired-event"),
        )
    watchtower._create_event("fresh-event", "TEST", "INVOICE", "INV-NEW", "INVOICE")
    with watchtower._db() as db:
        expired = db.execute(
            "SELECT event_id FROM watchtower_events WHERE event_id='expired-event'"
        ).fetchone()
        fresh = db.execute(
            "SELECT event_id FROM watchtower_events WHERE event_id='fresh-event'"
        ).fetchone()
    assert expired is None
    assert fresh is not None


def test_paypal_webhook_rejects_unverified_transmissions(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(watchtower, "_verify_paypal_signature", lambda headers, event, raw: False)
    response = client.post("/api/v1/watchtower/paypal/webhook", json={
        "id": "WH-EVENT-1",
        "event_type": "INVOICING.INVOICE.SENT",
        "resource": {"id": "INV-1"},
    })
    assert response.status_code == 401
    assert "could not be verified" in response.json()["detail"]
    assert client.get(
        "/api/v1/watchtower/events",
        headers={"X-Watchtower-Token": "test-watchtower-token"},
    ).json()["events"] == []


def test_verified_paypal_webhook_is_recorded_once_and_wakes_agent(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    scheduled = []
    monkeypatch.setattr(watchtower, "_schedule", lambda event_id, public_trace: scheduled.append(event_id))
    monkeypatch.setattr(watchtower, "_verify_paypal_signature", lambda headers, event, raw: True)
    payload = {
        "id": "WH-EVENT-2",
        "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
        "resource": {"id": "I-SUB-123"},
    }
    first = client.post("/api/v1/watchtower/paypal/webhook", json=payload)
    second = client.post("/api/v1/watchtower/paypal/webhook", json=payload)
    assert first.status_code == 202
    assert first.json()["event"]["source"] == "VERIFIED_PAYPAL_WEBHOOK"
    assert first.json()["event"]["identifier_hint"] == "SUBSCRIPTION"
    assert second.status_code == 202
    assert second.json()["duplicate"] is True
    assert scheduled == ["WH-EVENT-2"]


def test_paypal_webhook_ignores_unsubscribed_event_types(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(watchtower, "_verify_paypal_signature", lambda headers, event, raw: True)
    response = client.post("/api/v1/watchtower/paypal/webhook", json={
        "id": "WH-EVENT-3",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"id": "CAPTURE-1"},
    })
    assert response.status_code == 202
    assert response.json()["ignored"] is True
    assert response.json()["reason"]
