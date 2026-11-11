from protection_policy import ProtectionAction, decide_protection


def test_high_risk_requires_human_when_payment_is_not_in_controlled_checkout():
    decision = decide_protection(risk_score=90, investigation_complete=True)
    assert decision.action == ProtectionAction.HUMAN_APPROVAL_REQUIRED
    assert decision.requires_human_approval is True
    assert decision.executable is False


def test_high_risk_can_hold_only_user_authorized_pre_capture_checkout():
    decision = decide_protection(
        risk_score=90,
        investigation_complete=True,
        checkout_controlled_by_app=True,
        payment_authorized_not_captured=True,
        user_enabled_automatic_holds=True,
    )
    assert decision.action == ProtectionAction.HOLD_SUPPORTED_CHECKOUT
    assert decision.executable is True
    assert decision.requires_human_approval is False


def test_webhook_alone_never_authorizes_payment_hold():
    decision = decide_protection(
        risk_score=95,
        investigation_complete=True,
        payment_authorized_not_captured=True,
        user_enabled_automatic_holds=True,
    )
    assert decision.action == ProtectionAction.HUMAN_APPROVAL_REQUIRED
    assert decision.executable is False


def test_incomplete_investigation_never_looks_safe():
    decision = decide_protection(risk_score=0, investigation_complete=False)
    assert decision.action == ProtectionAction.REQUEST_VERIFICATION
    assert decision.requires_human_approval is True
