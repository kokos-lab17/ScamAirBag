"""Small adapter for dispatching minimized indexing jobs to Render Workflows."""
from __future__ import annotations

import os
from typing import Any, Dict, List


def dispatch_anonymized_case(
    domains: List[str], indicator_ids: List[str], risk_score: int,
) -> Dict[str, Any]:
    """Start the configured Render task; never send user content or PayPal IDs."""
    task_slug = os.getenv("RENDER_INDEX_TASK_SLUG")
    if not os.getenv("RENDER_API_KEY") or not task_slug:
        return {"dispatched": False, "reason": "RENDER_WORKFLOW_NOT_CONFIGURED"}

    from render import Render

    client = Render()
    run = client.workflows.start_task(
        task_slug,
        {
            "domains": domains[:10],
            "indicator_ids": indicator_ids[:30],
            "risk_score": max(0, min(100, int(risk_score))),
        },
    )
    return {"dispatched": True, "task_run_id": run.id, "status": run.status}
