"""Pure validation helpers for grounding extracted evidence in user text."""

from __future__ import annotations

import re
from typing import Optional


def explicit_message_identifier(text: Optional[str], identifier: Optional[str], hint: Optional[str]) -> bool:
    """Return True only when an ID appears beside an explicit type label in the message.

    This prevents an arbitrary malformed link fragment or an LLM guess from
    being sent to a PayPal endpoint as an invoice/order/subscription ID.
    """
    if not text or not identifier or not hint:
        return False
    kind = hint.strip().upper()
    label_patterns = {
        "INVOICE": r"\binvoice(?:\s+(?:id|number|no\.?))?\s*[:#-]?\s*",
        "ORDER": r"\border(?:\s+(?:id|number|no\.?))?\s*[:#-]?\s*",
        "SUBSCRIPTION": r"\bsubscription(?:\s+(?:id|number|no\.?))?\s*[:#-]?\s*",
    }
    label = label_patterns.get(kind)
    if not label:
        return False
    # Compare the exact candidate after a clear type label. Keep the candidate
    # boundary conservative so adjacent prose is not accidentally captured.
    pattern = re.compile(label + r"([A-Za-z0-9][A-Za-z0-9_-]{3,})", re.IGNORECASE)
    return any(match.group(1).casefold() == identifier.strip().casefold()
               for match in pattern.finditer(text))


