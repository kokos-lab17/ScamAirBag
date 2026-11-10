"""
schemas.py - The definitive data contracts and state models for ScamAirbag.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ==============================================================================
# 1. Provenance & Classification Enums
# ==============================================================================

class EvidenceProvenance(str, Enum):
    """Tracks the exact origin and verification level of every piece of data."""
    VERIFIED_PAYPAL = "VERIFIED_PAYPAL"       # Direct response from PayPal Sandbox API
    OBSERVED_EXTERNAL = "OBSERVED_EXTERNAL"   # Real DNS / WHOIS / Registrar lookups
    AI_INFERRED = "AI_INFERRED"               # Extracted or inferred by LLM forensic analysis
    UNAVAILABLE = "UNAVAILABLE"               # Requested check failed, timed out, or had no data
    HISTORICAL_CASE = "HISTORICAL_CASE"         # Prior opt-in, minimized investigation record


class DomainStatus(str, Enum):
    """Granular results for domain intelligence to avoid conflating NXDOMAIN with timeouts."""
    RESOLVED = "RESOLVED"
    NXDOMAIN = "NXDOMAIN"
    DNS_TIMEOUT = "DNS_TIMEOUT"
    WHOIS_TIMEOUT = "WHOIS_TIMEOUT"
    WHOIS_UNAVAILABLE = "WHOIS_UNAVAILABLE"
    SSRF_BLOCKED = "SSRF_BLOCKED"


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendedAction(str, Enum):
    """Defensible recommendations accounting for uncertainty and risk."""
    ABORT_PAYMENT = "ABORT_PAYMENT"
    PROCEED_WITH_MANUAL_VERIFICATION = "PROCEED_WITH_MANUAL_VERIFICATION"
    NO_MAJOR_RISK_INDICATORS_FOUND = "NO_MAJOR_RISK_INDICATORS_FOUND"


# ==============================================================================
# 2. Input & Entity Extraction Schemas
# ==============================================================================

class InvestigationInput(BaseModel):
    """Captures initial user submission while preserving clear boundaries."""
    user_text: Optional[str] = Field(default=None, description="Untrusted message, email, or chat text")
    email_headers: Optional[str] = Field(default=None, description="Optional raw email headers for authentication-result inspection")
    identifier: Optional[str] = Field(default=None, description="Transaction identifier (Invoice ID, Order ID, etc.)")
    identifier_hint: Optional[str] = Field(
        default=None,
        description="Hint: 'INVOICE', 'ORDER', 'SUBSCRIPTION', or 'UNKNOWN'"
    )
    share_anonymized_intelligence: bool = Field(
        default=False, description="Explicit consent to store minimized investigation indicators"
    )


class InvestigateRequest(BaseModel):
    """FastAPI payload model."""
    user_text: Optional[str] = None
    identifier: Optional[str] = None
    identifier_hint: Optional[str] = "UNKNOWN"
    share_anonymized_intelligence: bool = False


class ExtractedEntities(BaseModel):
    """
    Forensically extracted elements from untrusted message context.
    All fields are AI_INFERRED until cross-referenced with PayPal or DNS.
    """
    claimed_seller_name: Optional[str] = Field(default=None, description="Name the seller identifies as")
    claimed_seller_email: Optional[str] = Field(default=None, description="Email address claimed by the seller")
    claimed_recipient_name: Optional[str] = Field(default=None, description="Payment recipient name claimed in text")
    extracted_identifier: Optional[str] = Field(default=None, description="Discovered invoice, order, or sub ID")
    identifier_hint: Optional[str] = Field(default=None, description="Inferred ID type: 'INVOICE', 'ORDER', etc.")
    detected_urls: List[str] = Field(
        default_factory=list,
        description="Complete URL strings explicitly present in the submitted message",
    )
    malformed_urls: List[str] = Field(
        default_factory=list,
        description="Incomplete or malformed link-like strings explicitly present in the message",
    )
    detected_domains: List[str] = Field(default_factory=list, description="All external web domains mentioned")
    link_context: List[str] = Field(
        default_factory=list,
        description="Short surrounding text explaining or referring to each detected link",
    )
    urgency_score: int = Field(default=1, ge=1, le=10, description="1 (relaxed) to 10 (panic/extreme pressure)")
    coercion_tactics: List[str] = Field(
        default_factory=list,
        description="e.g., 'artificial_deadline', 'friends_and_family_diversion', 'threat_of_cancellation'"
    )
    unusual_payment_instructions: List[str] = Field(
        default_factory=list,
        description="e.g., 'demands_gift_card', 'third_party_wire', 'secrecy_demanded'"
    )
    raw_evidence_quotes: List[str] = Field(
        default_factory=list,
        description="Verbatim text snippets supporting the findings"
    )


# ==============================================================================
# 3. Tool Execution & Agent State Schemas
# ==============================================================================

class ToolExecutionResult(BaseModel):
    tool_name: str
    status: str = Field(..., description="'SUCCESS', 'FAILED', or 'NOT_APPLICABLE'")
    provenance: EvidenceProvenance
    data: Dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class AgentDecision(BaseModel):
    """The explicit contract for what the agent decides to do next."""
    action: str = Field(..., description="'CALL_TOOL' or 'FINISH'")
    selected_tool: Optional[str] = Field(default=None, description="Name of the tool to execute")
    rationale: str = Field(..., description="Forensic reasoning behind choosing this tool or stopping")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments to pass to the tool")


class InvestigationStep(BaseModel):
    step_number: int
    decision: AgentDecision
    result: Optional[ToolExecutionResult] = None


class SourceOutcome(BaseModel):
    """Tracks coverage and applicability per potential data source."""
    source_name: str  # e.g., 'paypal_invoice', 'paypal_order', 'domain_intelligence', 'message_context'
    applicable: bool
    status: str       # 'VERIFIED', 'FAILED', 'NOT_APPLICABLE', 'SKIPPED'
    provenance: EvidenceProvenance
    error_code: Optional[str] = None


# ==============================================================================
# 4. Scoring & Final Scorecard Schemas
# ==============================================================================

class Finding(BaseModel):
    rule_id: str
    description: str
    severity: RiskLevel
    provenance: EvidenceProvenance
    risk_impact: int = Field(..., ge=0, le=100)
    supporting_evidence: str


class AirbagScorecard(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Computed risk index")
    coverage_score: int = Field(..., ge=0, le=100, description="Percentage of applicable checks completed")
    confidence_level: str = Field(..., description="'HIGH', 'MEDIUM', or 'LOW'")
    recommended_action: RecommendedAction
    executive_summary: str
    findings: List[Finding]
    unverified_claims: List[str] = Field(
        default_factory=list,
        description="Claims made in text that could not be corroborated with verified data"
    )


class InvestigationTrace(BaseModel):
    """Complete, auditable trace of the investigation."""
    input_context: InvestigationInput
    status: str = Field(default="PARTIAL", description="COMPLETED, PARTIAL, or FAILED")
    error_code: Optional[str] = None
    background_job_id: Optional[str] = None
    background_job_status: Optional[str] = None
    extracted_entities: Optional[ExtractedEntities] = None
    steps: List[InvestigationStep] = Field(default_factory=list)
    source_outcomes: List[SourceOutcome] = Field(default_factory=list)
    final_scorecard: Optional[AirbagScorecard] = None


# ==============================================================================
# 5. Streaming Event Contracts (SSE)
# ==============================================================================

class InvestigationEventType(str, Enum):
    INVESTIGATION_STARTED = "investigation_started"
    DECISION_MADE = "decision_made"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    SCORECARD_READY = "scorecard_ready"
    INVESTIGATION_DONE = "investigation_done"
    ERROR = "error"


class InvestigationEvent(BaseModel):
    event_type: InvestigationEventType
    step_number: int = 0
    tool_name: Optional[str] = None
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
