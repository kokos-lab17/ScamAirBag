"""Policy boundary for ScamAirbag's autonomous protection loop.

The agent may investigate and recommend actions autonomously. A reversible
payment hold is permitted only when a first-party checkout adapter confirms
that the transaction is app-controlled and authorised but not captured.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ProtectionAction(str, Enum):
    CONTINUE_MONITORING = "CONTINUE_MONITORING"
    NOTIFY_USER = "NOTIFY_USER"
    REQUEST_VERIFICATION = "REQUEST_VERIFICATION"
    HOLD_SUPPORTED_CHECKOUT = "HOLD_SUPPORTED_CHECKOUT"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"


@dataclass(frozen=True)
class ProtectionDecision:
    action: ProtectionAction
    reason: str
    risk_score: int
    requires_human_approval: bool
    executable: bool
    limitation: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "requires_human_approval": self.requires_human_approval,
            "executable": self.executable,
            "limitation": self.limitation,
        }


def decide_protection(
    *,
    risk_score: int,
    investigation_complete: bool,
    checkout_controlled_by_app: bool = False,
    payment_authorized_not_captured: bool = False,
    user_enabled_automatic_holds: bool = False,
) -> ProtectionDecision:
    """Choose the strongest action allowed by evidence and integration state.

    A webhook or risk score alone never authorises a payment operation.
    """
    score = max(0, min(100, int(risk_score)))
    if not investigation_complete:
        return ProtectionDecision(
            ProtectionAction.REQUEST_VERIFICATION,
            "The investigation is incomplete; missing evidence must not be treated as a clean result.",
            score, True, False,
            "No payment-control action is available from an incomplete investigation.",
        )
    if score >= 70:
        if checkout_controlled_by_app and payment_authorized_not_captured and user_enabled_automatic_holds:
            return ProtectionDecision(
                ProtectionAction.HOLD_SUPPORTED_CHECKOUT,
                "High-risk indicators were found while this app-controlled payment is authorised but not captured.",
                score, False, True,
                "This hold applies only to the checkout transaction controlled by this integration.",
            )
        return ProtectionDecision(
            ProtectionAction.HUMAN_APPROVAL_REQUIRED,
            "High-risk indicators were found. Stop and verify the payment through an independent official channel.",
            score, True, False,
            "ScamAirbag cannot freeze, cancel, or reverse an unrelated PayPal payment.",
        )
    if score >= 35:
        return ProtectionDecision(
            ProtectionAction.REQUEST_VERIFICATION,
            "Risk indicators or evidence gaps require independent verification before payment.",
            score, True, False,
        )
    if score > 0:
        return ProtectionDecision(
            ProtectionAction.NOTIFY_USER,
            "A limited risk signal was observed; keep the user informed without claiming the payment is unsafe.",
            score, False, False,
        )
    return ProtectionDecision(
        ProtectionAction.CONTINUE_MONITORING,
        "No major indicators were found in the checks completed; monitoring continues.",
        score, False, False,
        "A low score is not a guarantee that a message or payment is safe.",
    )
