"""Persistent event-driven Watchtower. Demo events are explicitly simulated."""
from __future__ import annotations
import asyncio, hmac, json, os, sqlite3, uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from fastapi import APIRouter, Header, HTTPException, Request
import requests
from tools import PAYPAL_BASE_URL, PAYPAL_TIMEOUT_SECONDS, _get_paypal_access_token
from pydantic import BaseModel, Field, field_validator
from agent import run_investigation
from schemas import InvestigationInput, InvestigationTrace

router = APIRouter(prefix="/api/v1/watchtower", tags=["Watchtower"])
_DB_PATH = os.getenv("WATCHTOWER_DB_PATH", "watchtower.sqlite3")
_DEMO_ENABLED = os.getenv("WATCHTOWER_DEMO_ENABLED", "false").lower() in {"1","true","yes"}
_INGEST_TOKEN = os.getenv("WATCHTOWER_INGEST_TOKEN", "")
_TASKS: set[asyncio.Task] = set()

def _now(): return datetime.now(timezone.utc).isoformat()
def _connect():
    path=Path(_DB_PATH)
    if str(path.parent) not in {"","."}: path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(path),timeout=10); db.row_factory=sqlite3.Row; return db

@contextmanager
def _db():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_watchtower():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS watchtower_events (
        event_id TEXT PRIMARY KEY, source TEXT NOT NULL, event_type TEXT NOT NULL,
        identifier TEXT NOT NULL, identifier_hint TEXT NOT NULL, status TEXT NOT NULL,
        received_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT,
        completed_at TEXT, result_json TEXT, error_code TEXT)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_watchtower_received ON watchtower_events(received_at DESC)")

def _row(r):
    return {"event_id":r["event_id"],"source":r["source"],"event_type":r["event_type"],
    "identifier":r["identifier"],"identifier_hint":r["identifier_hint"],"status":r["status"],
    "received_at":r["received_at"],"updated_at":r["updated_at"],"started_at":r["started_at"],
    "completed_at":r["completed_at"],"result":json.loads(r["result_json"]) if r["result_json"] else None,
    "error_code":r["error_code"]}

class WatchtowerEventRequest(BaseModel):
    event_id:str=Field(min_length=1,max_length=180)
    event_type:str=Field(min_length=1,max_length=100)
    identifier:str=Field(min_length=1,max_length=200)
    identifier_hint:str
    @field_validator("identifier_hint")
    @classmethod
    def valid_hint(cls,v):
        v=v.strip().upper()
        if v not in {"INVOICE","ORDER","SUBSCRIPTION"}: raise ValueError("identifier_hint must be INVOICE, ORDER, or SUBSCRIPTION")
        return v
    @field_validator("event_id","event_type","identifier")
    @classmethod
    def strip_values(cls,v):
        v=v.strip()
        if not v: raise ValueError("Value cannot be blank")
        return v

class DemoEventRequest(BaseModel):
    identifier:str=Field(min_length=1,max_length=200)
    identifier_hint:str="INVOICE"
    @field_validator("identifier_hint")
    @classmethod
    def invoice_only(cls,v):
        if v.strip().upper()!="INVOICE": raise ValueError("The first demo currently supports PayPal Sandbox invoices only")
        return "INVOICE"

def _require_ingest_token(token:Optional[str]):
    if not _INGEST_TOKEN or not token or not hmac.compare_digest(_INGEST_TOKEN,token):
        raise HTTPException(status_code=401,detail="A valid Watchtower ingest token is required.")

def _create_event(event_id,source,event_type,identifier,hint):
    now=_now()
    with _db() as db:
        cursor=db.execute("""INSERT OR IGNORE INTO watchtower_events
        (event_id,source,event_type,identifier,identifier_hint,status,received_at,updated_at)
        VALUES (?,?,?,?,?,'RECEIVED',?,?)""",(event_id,source,event_type,identifier,hint,now,now))
        inserted = cursor.rowcount == 1
        r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
    return _row(r), not inserted

def _update(event_id,**values):
    allowed={"status","started_at","completed_at","result_json","error_code"}
    fields={k:v for k,v in values.items() if k in allowed}; fields["updated_at"]=_now()
    sql=", ".join(f"{k}=?" for k in fields)
    with _db() as db: db.execute(f"UPDATE watchtower_events SET {sql} WHERE event_id=?",(*fields.values(),event_id))

def _build_watchtower_alert(trace: InvestigationTrace) -> Dict[str, Any]:
    scorecard = trace.final_scorecard
    if scorecard is None:
        return {"level": "INCOMPLETE", "needs_attention": True, "title": "Investigation incomplete",
                "message": "No scorecard was produced. Verify through PayPal directly."}
    score = int(scorecard.risk_score)
    action = getattr(scorecard.recommended_action, "value", str(scorecard.recommended_action))
    if score >= 70:
        level, title = "CRITICAL", "High-risk indicators detected"
    elif score >= 35:
        level, title = "HIGH", "Suspicious payment activity needs review"
    elif score >= 20:
        level, title = "MEDIUM", "Some risk indicators need review"
    elif score > 0:
        level, title = "LOW", "A small number of indicators were observed"
    else:
        level, title = "INFO", "No scored indicators were found"
    incomplete = trace.status != "COMPLETED"
    needs_attention = incomplete or action in {"ABORT_PAYMENT", "PROCEED_WITH_MANUAL_VERIFICATION"}
    if action == "ABORT_PAYMENT":
        title = "High-risk indicators detected — do not pay yet"
    elif action == "PROCEED_WITH_MANUAL_VERIFICATION":
        title = "Pause and verify before paying"
    if incomplete:
        title = "Investigation incomplete — verify manually"
    top_findings = [
        item.description for item in sorted(
            scorecard.findings, key=lambda finding: finding.risk_impact, reverse=True
        )[:3]
    ]
    return {
        "level": "INCOMPLETE" if incomplete else level,
        "needs_attention": needs_attention,
        "title": title,
        "message": "Pause and verify through an official PayPal channel before paying."
                   if needs_attention else "Review the evidence; this is not a guarantee of safety.",
        "risk_score": score,
        "coverage_score": int(scorecard.coverage_score),
        "confidence_level": scorecard.confidence_level,
        "recommended_action": action,
        "top_findings": top_findings,
    }


async def _investigate_event(event_id,public_trace):
    now = _now()
    with _db() as db:
        claimed = db.execute(
            "UPDATE watchtower_events SET status='INVESTIGATING', started_at=?, updated_at=? WHERE event_id=? AND status='RECEIVED'",
            (now, now, event_id),
        )
        if claimed.rowcount != 1:
            return
        r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
    try:
        payload=InvestigationInput(identifier=r["identifier"],identifier_hint=r["identifier_hint"])
        trace=await asyncio.to_thread(run_investigation,payload)
        result=public_trace(trace)
        result["watchtower_alert"] = _build_watchtower_alert(trace)
        status="COMPLETED" if trace.status=="COMPLETED" else "PARTIAL" if trace.status=="PARTIAL" else "FAILED"
        _update(event_id,status=status,completed_at=_now(),result_json=json.dumps(result,separators=(",",":"),ensure_ascii=False),error_code=trace.error_code)
    except Exception:
        _update(event_id,status="FAILED",completed_at=_now(),error_code="WATCHTOWER_INVESTIGATION_FAILED")

def _schedule(event_id,public_trace):
    task=asyncio.create_task(_investigate_event(event_id,public_trace)); _TASKS.add(task); task.add_done_callback(_TASKS.discard)


def _verify_paypal_signature(headers: Dict[str, str], event: Dict[str, Any], raw_body: bytes) -> bool:
    webhook_id = os.getenv("PAYPAL_WEBHOOK_ID", "").strip()
    if not webhook_id:
        return False
    required = {
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_time": headers.get("paypal-transmission-time"),
        "cert_url": headers.get("paypal-cert-url"),
        "auth_algo": headers.get("paypal-auth-algo"),
        "transmission_sig": headers.get("paypal-transmission-sig"),
    }
    if not all(required.values()):
        return False
    token = _get_paypal_access_token()
    # Embed the original webhook JSON bytes verbatim. PayPal warns that
    # parse-and-reserialize can invalidate postback verification.
    envelope = json.dumps(required | {"webhook_id": webhook_id}, separators=(",", ":")).encode("utf-8")
    request_body = envelope[:-1] + b',"webhook_event":' + raw_body + b'}'
    response = requests.post(
        f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=request_body,
        timeout=PAYPAL_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json().get("verification_status") == "SUCCESS"


async def resume_watchtower_jobs(public_trace: Callable[[InvestigationTrace], Dict[str, Any]]) -> None:
    """Recover queued/interrupted work after an API process starts."""
    init_watchtower()
    with _db() as db:
        # This app currently runs as one API worker. Re-queue interrupted jobs;
        # the atomic claim in _investigate_event prevents duplicate execution.
        db.execute(
            "UPDATE watchtower_events SET status='RECEIVED', updated_at=? WHERE status='INVESTIGATING'",
            (_now(),),
        )
        rows = db.execute(
            "SELECT event_id FROM watchtower_events WHERE status='RECEIVED' ORDER BY received_at ASC"
        ).fetchall()
    for row in rows:
        _schedule(row["event_id"], public_trace)


def build_watchtower_router(public_trace:Callable[[InvestigationTrace],Dict[str,Any]])->APIRouter:
    init_watchtower()
    @router.get("/status")
    async def status():
        with _db() as db:
            counts={r["status"]:r["count"] for r in db.execute("SELECT status,COUNT(*) AS count FROM watchtower_events GROUP BY status")}
            latest=db.execute("SELECT received_at FROM watchtower_events ORDER BY received_at DESC LIMIT 1").fetchone()
        return {"service":"watchtower","state":"READY","demo_enabled":_DEMO_ENABLED,
        "authenticated_ingest_configured":bool(_INGEST_TOKEN),"paypal_webhook_configured":bool(os.getenv("PAYPAL_WEBHOOK_ID") and os.getenv("PAYPAL_CLIENT_ID") and os.getenv("PAYPAL_CLIENT_SECRET")),"paypal_webhook_path":"/api/v1/watchtower/paypal/webhook","accepted_paypal_event_types":["INVOICING.INVOICE.CREATED","INVOICING.INVOICE.SENT","INVOICING.INVOICE.UPDATED","CHECKOUT.ORDER.APPROVED","BILLING.SUBSCRIPTION.CREATED","BILLING.SUBSCRIPTION.ACTIVATED","BILLING.SUBSCRIPTION.UPDATED"],"storage":"sqlite",
        "storage_note":"History survives restarts only when the host has persistent disk storage.",
        "counts":counts,"last_event_at":latest["received_at"] if latest else None,
        "monitoring_claim":"Event listener is ready; it does not poll PayPal or receive PayPal webhooks until a verified external source is configured."}
    @router.get("/events")
    async def events(limit:int=30):
        limit=max(1,min(limit,100))
        with _db() as db: rows=db.execute("SELECT * FROM watchtower_events ORDER BY received_at DESC LIMIT ?",(limit,)).fetchall()
        return {"events":[_row(r) for r in rows]}
    @router.get("/events/{event_id}")
    async def event_detail(event_id:str):
        with _db() as db: r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
        if r is None: raise HTTPException(status_code=404,detail="Watchtower event not found.")
        return _row(r)
    @router.post("/events",status_code=202)
    async def ingest(payload:WatchtowerEventRequest,x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
        record, duplicate = _create_event(payload.event_id,"TOKEN_AUTHENTICATED_INGEST",payload.event_type,payload.identifier,payload.identifier_hint)
        if not duplicate:
            _schedule(record["event_id"],public_trace)
        return {"accepted":True,"duplicate":duplicate,"event":record}

    @router.post("/paypal/webhook", status_code=202)
    async def paypal_webhook(request: Request):
        raw_body = await request.body()
        try:
            event = json.loads(raw_body)
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="Invalid webhook JSON.")
        if not isinstance(event, dict):
            raise HTTPException(status_code=400, detail="Invalid webhook payload.")
        headers = {key.lower(): value for key, value in request.headers.items()}
        try:
            verified = await asyncio.to_thread(_verify_paypal_signature, headers, event, raw_body)
        except Exception:
            raise HTTPException(status_code=503, detail="PayPal webhook verification is temporarily unavailable.")
        if not verified:
            raise HTTPException(status_code=401, detail="PayPal webhook signature could not be verified.")
        event_type = str(event.get("event_type") or "")
        event_hints = {
            "INVOICING.INVOICE.CREATED": "INVOICE",
            "INVOICING.INVOICE.SENT": "INVOICE",
            "INVOICING.INVOICE.UPDATED": "INVOICE",
            "CHECKOUT.ORDER.APPROVED": "ORDER",
            "BILLING.SUBSCRIPTION.CREATED": "SUBSCRIPTION",
            "BILLING.SUBSCRIPTION.ACTIVATED": "SUBSCRIPTION",
            "BILLING.SUBSCRIPTION.UPDATED": "SUBSCRIPTION",
        }
        identifier_hint = event_hints.get(event_type)
        if identifier_hint is None:
            return {"accepted": True, "ignored": True, "reason": "Event type is outside the configured pre-payment monitoring allowlist."}
        resource = event.get("resource") or {}
        resource_id, event_id = resource.get("id"), event.get("id")
        if not isinstance(resource_id, str) or not resource_id.strip() or not isinstance(event_id, str) or not event_id.strip():
            raise HTTPException(status_code=400, detail="Verified PayPal event is missing its event or resource ID.")
        record, duplicate = _create_event(event_id, "VERIFIED_PAYPAL_WEBHOOK", event_type, resource_id.strip(), identifier_hint)
        if not duplicate:
            _schedule(event_id, public_trace)
        return {"accepted": True, "duplicate": duplicate, "event": record}

    @router.post("/demo/simulate-invoice",status_code=202)
    async def simulate(payload:DemoEventRequest):
        if not _DEMO_ENABLED: raise HTTPException(status_code=404,detail="Watchtower demo simulation is disabled.")
        event_id="demo-"+uuid.uuid4().hex
        record, _duplicate = _create_event(event_id,"SANDBOX_SIMULATED","PAYPAL_SANDBOX_INVOICE_EVENT_SIMULATED",payload.identifier,"INVOICE")
        _schedule(event_id,public_trace)
        return {"accepted":True,"event":record,"notice":"Simulated trigger only. ScamAirbag will attempt a real PayPal Sandbox invoice lookup; this is not a live PayPal webhook."}
    return router
