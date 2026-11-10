"""Safely patch the current ScamAirbag agent without replacing its integrations.

Run from the project root: python patch_agent.py
A backup named agent.py.before_verdict_patch is created first.
"""
from pathlib import Path
import shutil

TARGET = Path(__file__).resolve().parent / "agent.py"
if not TARGET.exists():
    raise SystemExit("agent.py was not found beside this script. Put patch_agent.py in the project root.")

source = TARGET.read_text(encoding="utf-8")
original = source

# 1) Do not send the extracted verbatim conversation/quotes back into the
# controller's repeated planning prompt. It only needs domains and typed IDs
# to decide which tool to call next.
old_extract = '''    elif result.tool_name == "extract_message_context":
        safe = {"entities": data.get("entities")}
'''
new_extract = '''    elif result.tool_name == "extract_message_context":
        entities = data.get("entities") or {}
        safe_entities = {
            "detected_domains": list(entities.get("detected_domains") or [])[:10],
            "extracted_identifier": entities.get("extracted_identifier"),
            "identifier_hint": entities.get("identifier_hint"),
        }
        safe = {"entities": safe_entities}
'''
if old_extract in source:
    source = source.replace(old_extract, new_extract, 1)
elif new_extract not in source:
    raise SystemExit("Could not locate the extract_message_context payload block. No files changed.")

# 2) Keep extracted entity context structured and non-verbatim. The controller
# needs domains, IDs and tactic labels, not quoted chunks of the conversation.
old_entities = '        "extracted_entities": _model_dump(extracted) if extracted else None,'
new_entities = """        \"extracted_entities\": ({
            \"extracted_identifier\": extracted.extracted_identifier,
            \"identifier_hint\": extracted.identifier_hint,
            \"detected_domains\": list(extracted.detected_domains or [])[:10],
            \"urgency_score\": extracted.urgency_score,
            \"coercion_tactics\": list(extracted.coercion_tactics or [])[:8],
            \"unusual_payment_instructions\": list(extracted.unusual_payment_instructions or [])[:8],
        } if extracted else None),"""
if old_entities in source:
    source = source.replace(old_entities, new_entities, 1)
elif new_entities not in source:
    raise SystemExit("Could not locate the extracted_entities prompt field. No files changed.")

# 3) After the initial extraction turn, do not repeat the entire user message
# in every model prompt. Preserve explicit PayPal ID inputs and type.
old_input = '        "input_context": _model_dump(input_context),'
new_input = '''        "input_context": {
            "has_user_text": bool(input_context.user_text),
            "identifier": input_context.identifier,
            "identifier_hint": input_context.identifier_hint,
        },'''
if old_input in source:
    source = source.replace(old_input, new_input, 1)
elif new_input not in source:
    raise SystemExit("Could not locate the _build_prompt input_context field. No files changed.")

# 4) Never let free-form model rationales leak into the activity stream or
# public trace. Replace them with fixed, tool-specific progress labels.
helper_anchor = '\ndef _function_response(types: Any, payload: Dict[str, Any]) -> Any:\n'
helper = '''\ndef _safe_decision_rationale(decision: AgentDecision) -> str:
    """Return a fixed UI-safe progress label; never expose model free text."""
    labels = {
        "extract_message_context": "Extract message indicators and explicitly labelled identifiers.",
        "paypal_invoice": "Verify the supplied invoice details with PayPal Sandbox.",
        "paypal_order": "Verify the supplied order details with PayPal Sandbox.",
        "paypal_subscription": "Verify the supplied subscription details with PayPal Sandbox.",
        "domain_intelligence": "Check DNS resolution and available domain registration details.",
        "historical_pattern_search": "Check the opt-in historical indicator store for matching context.",
        "threat_intelligence": "Check the configured external domain reputation source.",
    }
    if decision.action == "CALL_TOOL":
        return labels.get(decision.selected_tool, "Run the next permitted evidence check.")
    return "Review the completed and unavailable evidence checks."

'''
if "def _safe_decision_rationale(" not in source:
    if helper_anchor not in source:
        raise SystemExit("Could not locate the function insertion point. No files changed.")
    source = source.replace(helper_anchor, helper + helper_anchor, 1)

emit_anchor = '''            _emit(
                event_callback,
                InvestigationEventType.DECISION_MADE,
'''
emit_replacement = '''            decision.rationale = _safe_decision_rationale(decision)
            _emit(
                event_callback,
                InvestigationEventType.DECISION_MADE,
'''
if "decision.rationale = _safe_decision_rationale(decision)" not in source:
    if emit_anchor not in source:
        raise SystemExit("Could not locate the decision event block. No files changed.")
    source = source.replace(emit_anchor, emit_replacement, 1)

# 5) Remove rationale text from the model's rolling history as well.
old_recent = '                "rationale": step.decision.rationale,\n'
if old_recent in source:
    source = source.replace(old_recent, "")

if source == original:
    print("agent.py already contains the verdict/prompt protections; no changes needed.")
else:
    backup = TARGET.with_name("agent.py.before_verdict_patch")
    if not backup.exists():
        shutil.copy2(TARGET, backup)
    TARGET.write_text(source, encoding="utf-8")
    print("Patched agent.py. Original backup: agent.py.before_verdict_patch")
