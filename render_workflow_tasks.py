"""Render Workflows service: asynchronous indexing of opted-in case indicators.

This workflow receives only minimized, non-identifying fields. It never receives
raw messages, PayPal IDs, seller/recipient email addresses, invoice contents,
or model prompts.

Deploy as a Render Workflow service with start command:
    python render_workflow_tasks.py
"""
from __future__ import annotations

from render import Retry, TaskContext, Workflows

app = Workflows(
    default_retry=Retry(max_retries=2, wait_duration_ms=1500, backoff_scaling=2),
    default_timeout=120,
)


@app.task(name="index_anonymized_case", timeout_seconds=120)
def index_anonymized_case(
    ctx: TaskContext,
    domains: list[str],
    indicator_ids: list[str],
    risk_score: int,
) -> dict:
    """Index consented indicators in Elastic with bounded retries."""
    from elastic_intelligence import store_opt_in_case

    case_id = store_opt_in_case(
        domains=domains,
        indicator_ids=indicator_ids,
        risk_score=risk_score,
    )
    return {"stored": bool(case_id), "case_id": case_id}


if __name__ == "__main__":
    app.start()
