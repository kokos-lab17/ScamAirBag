"""
main.py - FastAPI application layer for ScamAirbag.

Install:
    pip install fastapi uvicorn

Run locally:
    uvicorn main:app --reload

Endpoints:
    GET  /health
    POST /api/v1/investigate
    POST /api/v1/investigate/stream

The streaming endpoint uses POST + fetch-readable Server-Sent Events. Native
browser EventSource does not support a JSON POST body, so the frontend should
consume this route with fetch() and parse the event stream.

Security notes:
- Never expose API credentials through responses or logs.
- Treat the submitted text and all investigation evidence as untrusted.
- Add authentication, rate limiting, HTTPS, and restrictive CORS before
  exposing this service publicly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, model_validator

from agent import run_investigation
from schemas import InvestigationInput, InvestigationTrace

logger = logging.getLogger("scamairbag.api")

APP_VERSION = "0.1.0"
MAX_USER_TEXT_CHARS = int(os.getenv("MAX_USER_TEXT_CHARS", "12000"))
MAX_IDENTIFIER_CHARS = 200
ALLOWED_IDENTIFIER_HINTS = {"UNKNOWN", "INVOICE", "ORDER", "SUBSCRIPTION"}


class InvestigationRequest(BaseModel):
    """Validated public API request; maps to the shared internal input schema."""

    user_text: Optional[str] = Field(
        default=None,
        max_length=MAX_USER_TEXT_CHARS,
        description="Message, email, or payment request to investigate.",
    )
    email_headers: Optional[str] = Field(default=None, max_length=12000, description="Optional raw email headers; do not include message body or unrelated personal data.")
    identifier: Optional[str] = Field(
        default=None,
        max_length=MAX_IDENTIFIER_CHARS,
        description="PayPal Sandbox invoice, order, or subscription ID.",
    )
    identifier_hint: str = Field(
        default="UNKNOWN",
        description="One of UNKNOWN, INVOICE, ORDER, or SUBSCRIPTION.",
    )
    share_anonymized_intelligence: bool = Field(
        default=False, description="Consent to store minimized, non-identifying case indicators."
    )

    @model_validator(mode="after")
    def validate_request(self) -> "InvestigationRequest":
        if not (self.user_text and self.user_text.strip()) and not (self.email_headers and self.email_headers.strip()) and not (
            self.identifier and self.identifier.strip()
        ):
            raise ValueError("Provide user_text, identifier, or both.")

        hint = self.identifier_hint.strip().upper()
        if hint not in ALLOWED_IDENTIFIER_HINTS:
            raise ValueError(
                "identifier_hint must be UNKNOWN, INVOICE, ORDER, or SUBSCRIPTION."
            )
        self.identifier_hint = hint

        if self.identifier is not None:
            self.identifier = self.identifier.strip() or None
        if self.user_text is not None:
            self.user_text = self.user_text.strip() or None
        if self.email_headers is not None:
            self.email_headers = self.email_headers.strip() or None

        if self.identifier is None and self.user_text is None and self.email_headers is None:
            raise ValueError("Provide a message, email headers, or a PayPal identifier.")
        if self.identifier is not None and hint == "UNKNOWN":
            raise ValueError("Select whether the PayPal ID is an invoice, order, or subscription.")
        return self

    def to_investigation_input(self) -> InvestigationInput:
        return InvestigationInput(
            user_text=self.user_text,
            email_headers=self.email_headers,
            identifier=self.identifier,
            identifier_hint=self.identifier_hint,
            share_anonymized_intelligence=self.share_anonymized_intelligence,
        )


app = FastAPI(
    title="ScamAirbag API",
    description=(
        "Autonomous pre-payment investigation using PayPal evidence, "
        "domain intelligence, and deterministic risk scoring."
    ),
    version=APP_VERSION,
)

# Local development defaults. For deployment, set CORS_ORIGINS to a
# comma-separated list of exact trusted frontend origins.
_raw_origins = os.getenv(
    "CORS_ORIGINS",
    "https://scamairbag-web-sqh8.onrender.com",
)
_allowed_origins = [
    origin.strip()
    for origin in _raw_origins.split(",")
    if origin.strip()
]

# Always permit common local development servers, even when .env contains
# only the deployed frontend origin. These are loopback origins, not wildcards.
_local_dev_origins = [
    f"http://{host}:{port}"
    for host in ("localhost", "127.0.0.1")
    for port in (3000, 5173, 5500, 5501)
]
_allowed_origins = list(dict.fromkeys(_allowed_origins + _local_dev_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


def _dump_model(value: Any) -> Dict[str, Any]:
    """Pydantic v2/v1-compatible JSON-safe serialization."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value.dict()


def _public_domain_evidence(trace: InvestigationTrace) -> list[Dict[str, Any]]:
    """Expose a strict allowlist of non-personal domain observations."""
    allowed = {
        "domain", "lookalike_observation", "initial_url", "initial_host", "final_host", "resolved_ips", "dns_status", "whois_status",
        "creation_date", "domain_age_days", "whois_available",
        "tls_status", "tls_checked", "tls_issuer", "tls_not_before",
        "tls_not_after", "tls_days_until_expiry", "tls_subject_alt_names",
        "tls_hostname_verified", "tls_error", "redirect_hops", "cross_domain_redirect", "https_downgrade", "redirect_loop_detected", "redirect_limit_reached", "blocked_unsafe_destination", "inspection_method",
    }
    evidence = []
    email_allowed = {"header_parse_status", "authentication_results", "received_spf_results",
                     "from_domain", "return_path_domain", "dkim_signing_domains",
                     "header_fields_present", "alignment_observations", "limitations"}
    for step in trace.steps:
        result = step.result
        if not result or result.tool_name not in {"domain_intelligence", "link_redirect_inspection", "email_authentication_headers"}:
            continue
        selected = email_allowed if result.tool_name == "email_authentication_headers" else allowed
        safe_data = {key: value for key, value in result.data.items() if key in selected}
        evidence.append({
            "tool_name": result.tool_name, "status": result.status,
            "provenance": result.provenance.value, "error_code": result.error_code,
            "observations": safe_data,
        })
    return evidence

def _public_trace(trace: InvestigationTrace) -> Dict[str, Any]:
    """Return an audit summary without echoing raw messages or raw tool payloads."""
    steps = []
    for step in trace.steps:
        result = step.result
        steps.append({
            "step_number": step.step_number,
            "tool_name": step.decision.selected_tool,
            # Do not expose model-generated rationale in the public audit response.
            "status": result.status if result else "DECISION_ONLY",
            "provenance": result.provenance.value if result else None,
            "error_code": result.error_code if result else None,
        })
    return {
        "status": trace.status,
        "error_code": trace.error_code,
        "background_job_id": trace.background_job_id,
        "background_job_status": trace.background_job_status,
        "input_summary": {
            "has_message": bool(trace.input_context.user_text),
            "has_email_headers": bool(trace.input_context.email_headers),
            "has_identifier": bool(trace.input_context.identifier),
            "identifier_hint": trace.input_context.identifier_hint,
        },
        "steps": steps,
        "source_outcomes": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item.dict()
            for item in trace.source_outcomes
        ],
        "domain_evidence": _public_domain_evidence(trace),
        "final_scorecard": (
            trace.final_scorecard.model_dump(mode="json")
            if trace.final_scorecard and hasattr(trace.final_scorecard, "model_dump")
            else trace.final_scorecard.dict() if trace.final_scorecard else None
        ),
    }


def _sse(event_name: str, payload: Dict[str, Any]) -> str:
    """Encode one standards-compliant SSE message."""
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Each JSON object is one line, but escape defensively for SSE framing.
    return f"event: {event_name}\ndata: {serialized}\n\n"


@app.get("/health")
async def health() -> Dict[str, str]:
    """Liveness endpoint; deliberately does not reveal secret configuration."""
    return {"status": "ok", "service": "scamairbag-api", "version": APP_VERSION}


@app.post("/api/v1/investigate", response_model=None)
async def investigate(payload: InvestigationRequest) -> JSONResponse:
    """
    Run one investigation and return the complete structured audit trace.

    run_investigation is synchronous, so it is offloaded to a worker thread to
    keep FastAPI's event loop responsive.
    """
    investigation_input = payload.to_investigation_input()
    try:
        trace: InvestigationTrace = await asyncio.to_thread(
            run_investigation, investigation_input
        )
        public_result = _public_trace(trace)
        return JSONResponse(
            content=public_result,
            status_code=503 if trace.status == "FAILED" else 200,
        )
    except Exception:
        logger.exception("Unhandled investigation request failure")
        raise HTTPException(
            status_code=500,
            detail="The investigation could not be completed.",
        )


@app.post("/api/v1/investigate/stream")
async def investigate_stream(
    payload: InvestigationRequest,
    request: Request,
) -> StreamingResponse:
    """
    Stream safe progress events while the synchronous agent runs in a thread.

    The callback transfers events from the worker thread to this async
    generator using loop.call_soon_threadsafe(). A final result event carries
    the structured trace so the frontend can render the completed scorecard.
    """
    investigation_input = payload.to_investigation_input()
    event_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    finished = object()

    def publish_event(event: Any) -> None:
        # Callback executes in the worker thread.
        try:
            event_payload = _dump_model(event)
            loop.call_soon_threadsafe(
                event_queue.put_nowait,
                ("progress", event_payload),
            )
        except RuntimeError:
            # The client disconnected and the event loop is shutting down.
            logger.debug("Progress event dropped after client disconnect.")

    def run_and_publish() -> InvestigationTrace:
        try:
            return run_investigation(
                investigation_input,
                event_callback=publish_event,
            )
        except Exception:
            logger.exception("Unexpected streaming investigation failure")
            raise

    async def event_generator():
        worker = asyncio.create_task(asyncio.to_thread(run_and_publish))
        try:
            yield ": scamairbag investigation stream\n\n"

            while True:
                if await request.is_disconnected():
                    worker.cancel()
                    break

                try:
                    item_type, item = await asyncio.wait_for(
                        event_queue.get(), timeout=0.75
                    )
                    if item_type == "progress":
                        event_name = item.get("event_type", "progress")
                        yield _sse(event_name, item)
                except asyncio.TimeoutError:
                    # Keep intermediaries/proxies from treating the stream as idle.
                    yield ": keep-alive\n\n"

                if worker.done():
                    # Drain events already queued by the worker before final output.
                    while not event_queue.empty():
                        queued_type, queued_item = event_queue.get_nowait()
                        if queued_type == "progress":
                            yield _sse(
                                queued_item.get("event_type", "progress"),
                                queued_item,
                            )
                    try:
                        trace = worker.result()
                        yield _sse("investigation_result", _public_trace(trace))
                    except Exception:
                        yield _sse("error", {
                            "message": "The investigation could not be completed.",
                            "error_code": "STREAMING_INVESTIGATION_FAILED",
                        })
                    break
        finally:
            if not worker.done():
                worker.cancel()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception("Unhandled API exception")
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
    )
