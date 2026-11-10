# ScamAirbag release notes

The earlier one-off dashboard/verdict patch instructions in this file are obsolete. Do not run the former `patch_agent.py` workflow; that script has been removed.

The maintained implementation is the application source in this repository. Install dependencies from `requirements.txt`, configure the environment described in `README.md`, and run the full regression suite with:

```bash
python -m compileall -q .
pytest -q
```

Current functionality includes event-driven PayPal Sandbox Watchtower, autonomous allowlisted evidence gathering, deterministic risk scoring, source provenance and coverage, domain/link/email observations, verified recurring subscription plan pricing, historical correlation, signed evidence receipts, production service-token protection, request limits, and evidence export/verification.

See `README.md` for the supported deployment and operating boundaries.