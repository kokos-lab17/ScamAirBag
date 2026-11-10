# ScamAirbag

**A pre-payment investigation workspace for suspicious PayPal payment requests.**

ScamAirbag combines user-provided payment context, PayPal Sandbox records, domain observations, and optional historical pattern intelligence. An AI agent chooses which evidence tools to call; Python validates and executes those calls; deterministic Python rules calculate the risk score and evidence coverage. The user remains responsible for the payment decision.

> ScamAirbag is an educational prototype. It does not guarantee that a payment or seller is safe, and it does not provide legal or financial advice.

## Architecture

```text
User message / explicit PayPal ID
                |
                v
        Gemini investigation agent
        - extracts claims and clues
        - chooses the next tool dynamically
                |
                v
        Python allowlisted dispatcher
          /          |           \
         v           v            v
   PayPal APIs   DNS / WHOIS   Elastic search
   invoice/order  domain facts  prior opt-in cases
   subscription
          \          |           /
           \         v          /
            Deterministic scoring
          - risk indicators
          - applicability-aware coverage
          - evidence provenance
                      |
                      v
            Scorecard + evidence grid

Optional: Render Workflows asynchronously indexes only consented,
minimized case indicators. It never receives raw messages or PayPal IDs.
```

### Technology responsibilities

- **PayPal REST API:** source of transaction evidence. The app uses OAuth client credentials and the Sandbox base URL by default.
- **Gemini (`google-genai`):** extracts untrusted message context and dynamically chooses allowlisted investigation tools. It does not calculate the final score.
- **Python:** validates model decisions, executes approved tools, calculates risk and coverage, and controls API response status.
- **AG Grid Community:** sortable/filterable evidence findings grid in the browser.
- **Elastic / Elasticsearch:** optional exact-domain lookup against historical records that users explicitly opted to contribute. Matches are contextual, not proof of fraud.
- **Render Workflows:** optional background task for indexing minimized, consented indicators.
- **Postman:** a collection is included for repeatable API checks.
- **APIMatic Context Plugin:** documented as a developer-time PayPal API context tool. It is not a runtime dependency and is not claimed as used until actually connected and used during development.

## Features and safeguards

- Correct PayPal seller fields: invoice `invoicer.email_address`; order `purchase_units[].payee.email_address`. Subscription `subscriber.email_address` is the payer, not the seller.
- Invoice private memo, recipient email addresses, and line-item descriptions are excluded from the invoice evidence payload.
- User-supplied PayPal IDs require an explicit type: invoice, order, or subscription. IDs extracted from a message are queried only when the model classifies their type.
- Domain checks are tracked separately per detected domain for DNS and WHOIS. An unchecked second domain cannot inherit the first domain's coverage.
- Failed lookups reduce coverage/confidence; they do not automatically add fraud risk.
- Invalid domain attempts are tracked from the agent's selected arguments, so a missing normalized result cannot trigger endless retries.
- Model-facing PayPal/domain evidence is minimized. Public API responses do not echo the raw submitted message or raw tool payloads.
- Investigation status is explicit: `COMPLETED`, `PARTIAL`, or `FAILED`. Missing Gemini configuration returns an HTTP 503 from the non-streaming endpoint.
- Elastic storage is disabled by default and requires both an explicit UI opt-in and `ELASTIC_STORE_CASES=true`.

## Run locally

Python 3.11 or 3.12 is recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements-dev.txt
cp .env.example .env
```

Fill in `.env` with your own credentials. Never commit `.env` or paste API secrets into chats.

Required for a full investigation:

- `GEMINI_API_KEY`
- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`

The default PayPal URL is the Sandbox endpoint:

```env
PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com
```

Optional WHOIS support:

```bash
pip install python-whois
```

Start the API:

```bash
uvicorn main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
python -m http.server 3000
```

Open `http://localhost:3000`.

## PayPal Sandbox setup

1. Create a PayPal Developer app in the Sandbox environment.
2. Copy its Sandbox Client ID and Secret into `.env`.
3. Create a test invoice/order/subscription in the same Sandbox account context.
4. Enter the identifier and choose its exact type in the UI.
5. Do not use arbitrary live customer identifiers. PayPal access is account- and authorization-scoped.

## Optional Elastic historical intelligence

Set:

```env
ELASTICSEARCH_URL=https://your-elasticsearch-endpoint
ELASTIC_API_KEY=your_api_key
ELASTIC_INDEX=scamairbag-investigations
ELASTIC_STORE_CASES=true
```

The agent can search exact-domain matches in historical opt-in records. The index stores only:

- detected domain names,
- finding rule IDs,
- a coarse risk band,
- timestamp and generated case ID.

It does **not** store message text, PayPal IDs, email addresses, invoice notes, or model prompts. Users must also check the optional consent box before a case is indexed. If Elastic is not configured, historical checks are marked not applicable and do not reduce coverage.

## Optional Render Workflows

The repository includes `render_workflow_tasks.py`, which defines an `index_anonymized_case` task using Render's Python Workflows SDK.

1. Deploy a Render Workflow service from this repository.
2. Use build command `pip install -r requirements.txt`.
3. Use start command `python render_workflow_tasks.py`.
4. Configure that workflow service with the same Elastic environment variables, including `ELASTIC_STORE_CASES=true`.
5. Copy its task slug and set these variables on the API service:

```env
RENDER_API_KEY=your_render_api_key
RENDER_INDEX_TASK_SLUG=your-workflow-slug/index_anonymized_case
```

Only minimized, consented fields are sent to Render: domains, finding rule IDs, and numeric risk score. If Render Workflows is not configured, the app falls back to a direct Elastic write (still requiring both opt-ins).

Render Workflows retains task arguments and results according to Render's service behavior, which is why this integration intentionally excludes raw user messages and transaction identifiers.

## Deploy to Render

A starter `render.yaml` defines the FastAPI service and static frontend. Review and set all secret environment variables in the Render Dashboard before deployment. The frontend defaults to `https://scamairbag.onrender.com` when hosted on Render; update that URL if your service name differs.

The static site origin in `CORS_ORIGINS` must exactly match the deployed frontend origin. Do not use wildcard CORS for a credential-bearing backend.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness check; does not reveal secret configuration |
| POST | `/api/v1/investigate` | Complete investigation response |
| POST | `/api/v1/investigate/stream` | Progress events and final result using POST + SSE |

The streaming endpoint must be consumed with `fetch()` and a readable response stream; native `EventSource` cannot send the JSON POST body.

### Example request

```json
{
  "user_text": "Please investigate this payment request.",
  "identifier": "YOUR_SANDBOX_INVOICE_ID",
  "identifier_hint": "INVOICE",
  "share_anonymized_intelligence": false
}
```

The API returns a public trace summary, not the raw submitted message or unfiltered tool results. The `status` field is `COMPLETED`, `PARTIAL`, or `FAILED`.

## Tests

```bash
pytest -q
python -m py_compile schemas.py tools.py elastic_intelligence.py scoring.py agent.py main.py render_dispatch.py render_workflow_tasks.py
```

The automated tests use mocks and do not require live Gemini, PayPal, Elastic, or Render credentials. Live integration tests must be run with your own Sandbox and service credentials.

## Postman

Import `postman/ScamAirbag.postman_collection.json` into Postman. Set `baseUrl` and replace `invoiceId` with an invoice created in your own PayPal Sandbox account.

## Sponsor/developer-tool notes

- **AG Grid:** the frontend uses AG Grid Community for a sortable, filterable evidence grid. AG Grid's sponsor page highlights AG Studio and its Studio Agent Framework for richer dashboard-building experiences; this code does not claim to use AG Studio.
- **Elastic:** the optional historical pattern search and opt-in indexer are real application integrations.
- **Render:** `render.yaml` supports deployment; the optional Render Workflows task handles asynchronous indexing.
- **APIMatic:** see [`docs/APIMATIC_CONTEXT_PLUGIN.md`](docs/APIMATIC_CONTEXT_PLUGIN.md). This is a developer workflow note, not a runtime integration.
- **Postman:** see the included collection for API testing.

## Security before public deployment

This prototype still needs authentication, per-user authorization, rate limiting, abuse monitoring, secret rotation, retention controls, and a formal privacy review before public use. Keep it on Sandbox credentials until those controls are implemented.
