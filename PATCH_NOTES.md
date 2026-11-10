# ScamAirbag verdict + dashboard update

## Files
- `frontend/index.html` — replacement dashboard page.
- `patch_agent.py` — safe, targeted patch for the current `agent.py`; preserves the existing tool integrations and creates `agent.py.before_verdict_patch` before editing.

## Apply
1. Copy `frontend/index.html` into your project's `frontend/` folder, replacing the existing file.
2. Copy `patch_agent.py` into the project root (beside `agent.py`).
3. From that root, run: `python patch_agent.py`
4. Run your existing test suite: `pytest -q`.

## What this fixes
- The controller no longer receives extracted verbatim message quotes or full extracted entities in follow-up planning prompts. It receives only structured domains, typed identifiers and tactic labels needed for tool selection.
- The user's full message is not repeated in the rolling prompt state after the initial request.
- Model-generated free-form rationales are replaced with fixed progress labels before being stored or streamed. This prevents copied message text from appearing as agent reasoning in the activity log.
- The dashboard does not display the free-form `executive_summary` field. It builds a concise verdict from the deterministic risk score, structured findings and evidence coverage.
- Findings use a full-width table with compact previews. Selecting a row reveals the full description and supporting evidence below it, rather than forcing very wide columns or giant rows.
- Wider responsive layout, section navigation, source coverage and activity are arranged below the main findings table.
- Corrected the default Render API endpoint to `https://scamairbag.onrender.com`.
- Fixed the previous frontend's stale `findings` element reference; the new page uses the actual findings grid and detail panel IDs.

## Important
This does not change deterministic scoring weights or claim that a low score means safe. VirusTotal remains optional and is not enabled by this patch. The frontend still displays the scorecard supplied by the backend, but deliberately avoids unstructured summary text.
