"""Persistent event-driven Watchtower. Demo events are explicitly simulated."""
from __future__ import annotations
import asyncio, hmac, json, os, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from fastapi import APIRouter, Header, HTTPException
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

def init_watchtower():
    with _connect() as db:
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
    with _connect() as db:
        db.execute("""INSERT OR IGNORE INTO watchtower_events
        (event_id,source,event_type,identifier,identifier_hint,status,received_at,updated_at)
        VALUES (?,?,?,?,?,'RECEIVED',?,?)""",(event_id,source,event_type,identifier,hint,now,now))
        r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
    return _row(r)

def _update(event_id,**values):
    allowed={"status","started_at","completed_at","result_json","error_code"}
    fields={k:v for k,v in values.items() if k in allowed}; fields["updated_at"]=_now()
    sql=", ".join(f"{k}=?" for k in fields)
    with _connect() as db: db.execute(f"UPDATE watchtower_events SET {sql} WHERE event_id=?",(*fields.values(),event_id))

async def _investigate_event(event_id,public_trace):
    with _connect() as db: r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
    if r is None or r["status"]!="RECEIVED": return
    _update(event_id,status="INVESTIGATING",started_at=_now())
    try:
        payload=InvestigationInput(identifier=r["identifier"],identifier_hint=r["identifier_hint"])
        trace=await asyncio.to_thread(run_investigation,payload)
        result=public_trace(trace)
        status="COMPLETED" if trace.status=="COMPLETED" else "PARTIAL" if trace.status=="PARTIAL" else "FAILED"
        _update(event_id,status=status,completed_at=_now(),result_json=json.dumps(result,separators=(",",":"),ensure_ascii=False),error_code=trace.error_code)
    except Exception:
        _update(event_id,status="FAILED",completed_at=_now(),error_code="WATCHTOWER_INVESTIGATION_FAILED")

def _schedule(event_id,public_trace):
    task=asyncio.create_task(_investigate_event(event_id,public_trace)); _TASKS.add(task); task.add_done_callback(_TASKS.discard)

def build_watchtower_router(public_trace:Callable[[InvestigationTrace],Dict[str,Any]])->APIRouter:
    init_watchtower()
    @router.get("/status")
    async def status():
        with _connect() as db:
            counts={r["status"]:r["count"] for r in db.execute("SELECT status,COUNT(*) AS count FROM watchtower_events GROUP BY status")}
            latest=db.execute("SELECT received_at FROM watchtower_events ORDER BY received_at DESC LIMIT 1").fetchone()
        return {"service":"watchtower","state":"READY","demo_enabled":_DEMO_ENABLED,
        "authenticated_ingest_configured":bool(_INGEST_TOKEN),"storage":"sqlite",
        "storage_note":"History survives restarts only when the host has persistent disk storage.",
        "counts":counts,"last_event_at":latest["received_at"] if latest else None,
        "monitoring_claim":"Event listener is ready; it does not poll PayPal or receive PayPal webhooks until a verified external source is configured."}
    @router.get("/events")
    async def events(limit:int=30):
        limit=max(1,min(limit,100))
        with _connect() as db: rows=db.execute("SELECT * FROM watchtower_events ORDER BY received_at DESC LIMIT ?",(limit,)).fetchall()
        return {"events":[_row(r) for r in rows]}
    @router.get("/events/{event_id}")
    async def event_detail(event_id:str):
        with _connect() as db: r=db.execute("SELECT * FROM watchtower_events WHERE event_id=?",(event_id,)).fetchone()
        if r is None: raise HTTPException(status_code=404,detail="Watchtower event not found.")
        return _row(r)
    @router.post("/events",status_code=202)
    async def ingest(payload:WatchtowerEventRequest,x_watchtower_token:Optional[str]=Header(default=None)):
        _require_ingest_token(x_watchtower_token)
        record=_create_event(payload.event_id,"TOKEN_AUTHENTICATED_INGEST",payload.event_type,payload.identifier,payload.identifier_hint)
        duplicate=record["status"]!="RECEIVED" or record["updated_at"]!=record["received_at"]
        if not duplicate: _schedule(record["event_id"],public_trace)
        return {"accepted":True,"duplicate":duplicate,"event":record}
    @router.post("/demo/simulate-invoice",status_code=202)
    async def simulate(payload:DemoEventRequest):
        if not _DEMO_ENABLED: raise HTTPException(status_code=404,detail="Watchtower demo simulation is disabled.")
        event_id="demo-"+uuid.uuid4().hex
        record=_create_event(event_id,"SANDBOX_SIMULATED","PAYPAL_SANDBOX_INVOICE_EVENT_SIMULATED",payload.identifier.strip(),"INVOICE")
        _schedule(event_id,public_trace)
        return {"accepted":True,"event":record,"notice":"Simulated trigger only. ScamAirbag will attempt a real PayPal Sandbox invoice lookup; this is not a live PayPal webhook."}
    return router
