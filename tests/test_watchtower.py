"""Watchtower API authentication, idempotency, and storage regressions."""
from fastapi.testclient import TestClient

import main
import watchtower


def _client(monkeypatch, tmp_path):
    monkeypatch.setattr(watchtower, "_DB_PATH", str(tmp_path / "watchtower.sqlite3"))
    monkeypatch.setattr(watchtower, "_INGEST_TOKEN", "test-watchtower-token")
    monkeypatch.setattr(watchtower, "_schedule", lambda event_id, public_trace: None)
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
