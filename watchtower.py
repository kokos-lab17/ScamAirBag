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
from agent import MAX_INVESTIGATION_SECONDS, run_investigation
from schemas import InvestigationInput, InvestigationTrace

router = APIRouter(prefix="/api/v1/watchtower", tags=["Watchtower"])
_DB_PATH = os.getenv("WATCHTOWER_DB_PATH", "watchtower.sqlite3")
_DEMO_ENABLED = os.getenv("WATCHTOWER_DEMO_ENABLED", "false").lower() in {"1","true","yes"}
_INGEST_TOKEN = os.getenv("WATCHTOWER_INGEST_TOKEN", "")
_TASKS: set[asyncio.Task] = set()
_WATCHTOWER_MAX_CONCURRENT = max(1, min(4, int(os.getenv("WATCHTOWER_MAX_CONCURRENT", "2"))))
_WORKER_SEMAPHORE = asyncio.Semaphore(_WATCHTOWER_MAX_CONCURRENT)

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
        db.execute("CREATE TABLE IF NOT EXISTS watchtower_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL)")

def _get_setting(key: str) -> Optional[str]:
    with _db() as db:
        row = db.execute("SELECT setting_value FROM watchtower_settings WHERE setting_key=?", (key,)).fetchone()
    return row["setting_value"] if row else None


def _set_setting(key: str, value: str) -> None:
    with _db() as db:
        db.execute(
            "INSERT INTO watchtower_settings(setting_key,setting_value) VALUES(?,?) "
            "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
            (key, value),
        )


PAYPAL_EVENT_HINTS = {
    "INVOICING.INVOICE.CREATED": "INVOICE",
    "INVOICING.INVOICE.SENT": "INVOICE",
    "INVOICING.INVOICE.UPDATED": "INVOICE",
    "CHECKOUT.ORDER.APPROVED": "ORDER",
    "BILLING.SUBSCRIPTION.CREATED": "SUBSCRIPTION",
    "BILLING.SUBSCRIPTION.ACTIVATED": "SUBSCRIPTION",
    "BILLING.SUBSCRIPTION.UPDATED": "SUBSCRIPTION",
    "BILLING.SUBSCRIPTION.SUSPENDED": "SUBSCRIPTION",
    "BILLING.SUBSCRIPTION.CANCELLED": "SUBSCRIPTION",
    "BILLING.SUBSCRIPTION.EXPIRED": "SUBSCRIPTION",
}


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


def _correlate_prior_domains(event_id: str, current_result: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Correlate exact observed domains across prior Watchtower cases, without treating repetition as proof."""
    current_domains = {
        item.get("observations", {}).get("domain")
        for item in current_result.get("domain_evidence", [])
        if isinstance(item, dict) and item.get("observations", {}).get("domain")
    }
    if not current_domains:
        return []
    with _db() as db:
        rows = db.execute(
            "SELECT received_at,result_json FROM watchtower_events "
            "WHERE event_id<>? AND status IN ('COMPLETED','PARTIAL') "
            "AND result_json IS NOT NULL ORDER BY received_at DESC LIMIT 250",
            (event_id,),
        ).fetchall()
    correlations = []
    for domain in sorted(current_domains):
        matches = []
        for row in rows:
            try:
                prior = json.loads(row["result_json"])
            except (TypeError, ValueError):
                continue
            prior_domains = {
                item.get("observations", {}).get("domain")
                for item in prior.get("domain_evidence", [])
                if isinstance(item, dict) and item.get("observations", {}).get("domain")
            }
            if domain in prior_domains:
                matches.append(row["received_at"])
        if matches:
            correlations.append({
                "domain": domain,
                "prior_case_observations": len(matches),
                "most_recent_prior_observation": matches[0],
                "interpretation": "Repeated appearance is contextual correlation only; it does not establish common ownership or fraud.",
            })
    return correlations


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
        payload=InvestigationInput(identifier=r["identifier"],identifier_hint=r["identifier_hint"],share_anonymized_intelligence=os.getenv("WATCHTOWER_SHARE_ANONYMIZED_INTELLIGENCE","false").lower() in {"1","true","yes"})
        trace=await asyncio.wait_for(
            asyncio.to_thread(run_investigation, payload),
            timeout=MAX_INVESTIGATION_SECONDS + 45,
        )
        result=public_trace(trace)
        correlations = _correlate_prior_domains(event_id, result)
        result["historical_correlations"] = correlations
        result["watchtower_alert"] = _build_watchtower_alert(trace)
        if correlations:
            result["watchtower_alert"]["historical_context"] = correlations
        status="COMPLETED" if trace.status=="COMPLETED" else "PARTIAL" if trace.status=="PARTIAL" else "FAILED"
        _update(event_id,status=status,completed_at=_now(),result_json=json.dumps(result,separators=(",",":"),ensure_ascii=False),error_code=trace.error_code)
    except asyncio.TimeoutError:
        _update(event_id,status="FAILED",completed_at=_now(),error_code="WATCHTOWER_INVESTIGATION_TIMEOUT")
    except Exception:
        _update(event_id,status="FAILED",completed_at=_now(),error_code="WATCHTOWER_INVESTIGATION_FAILED")

def _schedule(event_id,public_trace):
    async def bounded_investigation():
        async with _WORKER_SEMAPHORE:
            await _investigate_event(event_id, public_trace)
    task=asyncio.create_task(bounded_investigation()); _TASKS.add(task); task.add_done_callback(_TASKS.discard)


def _verify_paypal_signature(headers: Dict[str, str], event: Dict[str, Any], raw_body: bytes) -> bool:
    webhook_id = (_get_setting("PAYPAL_WEBHOOK_ID") or os.getenv("PAYPAL_WEBHOOK_ID", "")).strip()
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
        "authenticated_ingest_configured":bool(_INGEST_TOKEN),"historical_case_storage_opt_in":os.getenv("WATCHTOWER_SHARE_ANONYMIZED_INTELLIGENCE","false").lower() in {"1","true","yes"},"paypal_webhook_configured":bool((_get_setting("PAYPAL_WEBHOOK_ID") or os.getenv("PAYPAL_WEBHOOK_ID")) and os.getenv("PAYPAL_CLIENT_ID") and os.getenv("PAYPAL_CLIENT_SECRET")),"paypal_webhook_path":"/api/v1/watchtower/paypal/webhook","accepted_paypal_event_types":list(PAYPAL_EVENT_HINTS.keys()),"public_api_url_configured":bool(os.getenv("WATCHTOWER_PUBLIC_API_URL")),"storage":"sqlite",
        "storage_note":"History survives restarts only when the host has persistent disk storage.",
        "counts":counts,"last_event_at":latest["received_at"] if latest else None,
        "monitoring_claim":"Event listener is ready; it does not poll PayPal or receive PayPal webhooks until a verified external source is configured."}
    @router.get("/events")
    async def events(limit:int=30, x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
        limit=max(1,min(limit,100))
        with _db() as db: rows=db.execute("SELECT * FROM watchtower_events ORDER BY received_at DESC LIMIT ?",(limit,)).fetchall()
        return {"events":[_row(r) for r in rows]}
    @router.get("/events/{event_id}")
    async def event_detail(event_id:str, x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
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

    @router.post("/paypal/register", status_code=201)
    async def register_paypal_webhook(x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
        existing = _get_setting("PAYPAL_WEBHOOK_ID") or os.getenv("PAYPAL_WEBHOOK_ID")
        if existing:
            return {"registered": True, "already_registered": True, "webhook_id": existing,
                    "webhook_url": os.getenv("WATCHTOWER_PUBLIC_API_URL", "").rstrip("/") + "/api/v1/watchtower/paypal/webhook",
                    "event_types": list(PAYPAL_EVENT_HINTS.keys())}
        if "sandbox" not in PAYPAL_BASE_URL.lower():
            raise HTTPException(status_code=400, detail="Watchtower webhook registration is restricted to PayPal Sandbox.")
        public_url = os.getenv("WATCHTOWER_PUBLIC_API_URL", "").strip().rstrip("/")
        if not public_url.startswith("https://"):
            raise HTTPException(status_code=400, detail="Set WATCHTOWER_PUBLIC_API_URL to the public HTTPS API origin before registering.")
        webhook_url = public_url + "/api/v1/watchtower/paypal/webhook"
        payload = {"url": webhook_url, "event_types": [{"name": name} for name in PAYPAL_EVENT_HINTS]}
        try:
            def create_webhook():
                token = _get_paypal_access_token()
                response = requests.post(
                    f"{PAYPAL_BASE_URL}/v1/notifications/webhooks",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json=payload, timeout=PAYPAL_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                return response.json()
            result = await asyncio.to_thread(create_webhook)
        except Exception:
            raise HTTPException(status_code=502, detail="PayPal webhook registration failed. Check Sandbox credentials and webhook API permissions.")
        webhook_id = result.get("id")
        if not isinstance(webhook_id, str) or not webhook_id:
            raise HTTPException(status_code=502, detail="PayPal did not return a webhook ID.")
        _set_setting("PAYPAL_WEBHOOK_ID", webhook_id)
        return {"registered": True, "already_registered": False, "webhook_id": webhook_id,
                "webhook_url": webhook_url, "event_types": list(PAYPAL_EVENT_HINTS.keys()),
                "note": "The webhook ID is stored in Watchtower SQLite. Set PAYPAL_WEBHOOK_ID in the service environment as a durable backup if the host does not use persistent storage."}

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
        event_hints = PAYPAL_EVENT_HINTS
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
    async def simulate(payload:DemoEventRequest, x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
        if not _DEMO_ENABLED: raise HTTPException(status_code=404,detail="Watchtower demo simulation is disabled.")
        event_id="demo-"+uuid.uuid4().hex
        record, _duplicate = _create_event(event_id,"SANDBOX_SIMULATED","PAYPAL_SANDBOX_INVOICE_EVENT_SIMULATED",payload.identifier,"INVOICE")
        _schedule(event_id,public_trace)
        return {"accepted":True,"event":record,"notice":"Simulated trigger only. ScamAirbag will attempt a real PayPal Sandbox invoice lookup; this is not a live PayPal webhook."}
    return router
