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
- **Python:** validates model decisions, grounds outbound targets, executes approved tools, calculates risk and coverage, builds tamper-evident evidence receipts, and controls API response status.
- **AG Grid Community:** sortable/filterable evidence findings grid in the browser.
- **Evidence receipt:** a downloadable, hash-verifiable manifest connecting findings to minimized source observations and provenance.
- **Elastic / Elasticsearch:** optional exact-domain lookup against historical records that users explicitly opted to contribute. Matches are contextual, not proof of fraud.
- **Render Workflows:** optional background task for indexing minimized, consented indicators.
- **Postman:** a collection is included for repeatable API checks.
- **APIMatic Context Plugin:** documented as a developer-time PayPal API context tool. It is not a runtime dependency and is not claimed as used until actually connected and used during development.

## Features and safeguards

- Correct PayPal seller fields: invoice `invoicer.email_address`; order `purchase_units[].payee.email_address`. Subscription `subscriber.email_address` is the payer, not the seller. Subscription investigations also retrieve the PayPal plan's verified billing-cycle price, currency, interval, status, and next billing time; plan-price availability is tracked as a separate coverage check.
- Invoice private memo, recipient email addresses, and line-item descriptions are excluded from the invoice evidence payload.
- User-supplied PayPal IDs require an explicit type: invoice, order, or subscription. IDs extracted from a message are queried only when the model classifies their type.
- Domain checks are tracked separately per detected domain for DNS and WHOIS. An unchecked second domain cannot inherit the first domain's coverage.
- Complete submitted links are inspected with pinned-IP HTTP HEAD requests; non-public DNS targets, unsupported ports, and unsafe redirect destinations are blocked. The page body is never downloaded.
- A disclosed brand-domain heuristic flags one-edit lookalikes, brand names embedded in subdomains, and IDN punycode. Similarity is a review lead, not proof of impersonation.
- Claimed payment amounts are compared with verified PayPal invoice/order totals only when the exact supporting quote is present and the currencies match.
- Risk findings include cross-domain redirects, HTTPS downgrades, email-authentication failure claims, and exact-domain historical correlations with explicit uncertainty labels.
- Every response includes a SHA-256 evidence manifest for minimized source observations and findings. Users can export it and verify record/root integrity; hashes are not source signatures or proof that an upstream provider's data was authentic.
- The agent is restricted to exact links/domains in the submitted message or seller domains returned by a verified PayPal record. It cannot invent outbound inspection targets.
- Failed lookups reduce coverage/confidence; they do not automatically add fraud risk.
- Invalid domain attempts are tracked from the agent's selected arguments, so a missing normalized result cannot trigger endless retries.
- Model-facing PayPal/domain evidence is minimized. Public API responses do not echo the raw submitted message or raw tool payloads.
- Investigation status is explicit: `COMPLETED`, `PARTIAL`, or `FAILED`. Missing Gemini configuration returns an HTTP 503 from the non-streaming endpoint.
- Production investigation and evidence-verification endpoints require a shared service token (`SCAM_AIRBAG_API_TOKEN`, falling back to `WATCHTOWER_INGEST_TOKEN`). Local development mode does not require this token. The API rejects unexpected request fields and bounds concurrent investigations.
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


## Airbag Watchtower (event-driven investigations)

Watchtower adds an event intake path that can wake the existing investigation agent without a user pasting a message or pressing the manual Investigate button.

**Supported paths:**

- **Verified PayPal Invoicing webhooks:** `POST /api/v1/watchtower/paypal/webhook` verifies the incoming transmission with PayPal's `/v1/notifications/verify-webhook-signature` API before trusting the event. The initial pre-payment allowlist includes invoice events `INVOICING.INVOICE.CREATED`, `INVOICING.INVOICE.SENT`, and `INVOICING.INVOICE.UPDATED`; order event `CHECKOUT.ORDER.APPROVED`; and subscription lifecycle events `BILLING.SUBSCRIPTION.CREATED`, `BILLING.SUBSCRIPTION.ACTIVATED`, `BILLING.SUBSCRIPTION.UPDATED`, `BILLING.SUBSCRIPTION.SUSPENDED`, `BILLING.SUBSCRIPTION.CANCELLED`, and `BILLING.SUBSCRIPTION.EXPIRED`. A verified event automatically schedules the matching PayPal Sandbox invoice, order, or subscription lookup and investigation.
- **Authenticated generic event intake:** `POST /api/v1/watchtower/events` requires the `X-Watchtower-Token` header matching `WATCHTOWER_INGEST_TOKEN`. The same token protects private event-history reads and the demo trigger; enter it in the Watchtower dashboard's access-token field. This is a trusted integration endpoint, not proof that the sender is PayPal.
- **Explicit demo simulator:** `POST /api/v1/watchtower/demo/simulate-invoice` is available only when `WATCHTOWER_DEMO_ENABLED=true`. The dashboard labels this as simulated. The investigation still attempts a real Sandbox invoice lookup; no invoice facts are fabricated.

### Configure a PayPal Sandbox webhook

1. Deploy the API over HTTPS and confirm `https://YOUR-API-HOST/api/v1/watchtower/status` responds.
2. Set `WATCHTOWER_PUBLIC_API_URL=https://YOUR-API-HOST` and configure the existing Sandbox `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` on the API service.
3. In the Watchtower dashboard, enter the `WATCHTOWER_INGEST_TOKEN` and click **Register PayPal webhook**. ScamAirbag creates the subscription with PayPal and saves the returned webhook ID in Watchtower settings.
4. Copy the returned webhook ID into the API service environment as `PAYPAL_WEBHOOK_ID` as a persistence backup, especially if the host does not provide a persistent disk.
5. Trigger a Sandbox invoice, order, or subscription event and check Watchtower's event feed. You can also manage subscriptions in the PayPal Developer Dashboard. Only events that pass PayPal's signature-verification API are recorded with source `VERIFIED_PAYPAL_WEBHOOK`. The handler preserves the original webhook body bytes when constructing PayPal's verification request, as PayPal warns that parsing and reserializing the event can invalidate verification.

Required/optional environment variables:

```env
PAYPAL_WEBHOOK_ID=your_sandbox_webhook_id
WATCHTOWER_PUBLIC_API_URL=https://your-api-host.onrender.com
WATCHTOWER_DEMO_ENABLED=true
WATCHTOWER_INGEST_TOKEN=use-a-long-random-secret-for-your-own-integration
WATCHTOWER_DB_PATH=/var/data/watchtower.sqlite3
WATCHTOWER_SHARE_ANONYMIZED_INTELLIGENCE=false
```

`WATCHTOWER_DB_PATH` must point to a mounted persistent disk path if event history must survive Render instance replacement/restarts. The Render blueprint now provisions a 1 GB persistent disk at `/var/data` and configures SQLite to use it. Autonomous case storage is off by default. Set `WATCHTOWER_SHARE_ANONYMIZED_INTELLIGENCE=true` only after explicitly opting in; actual storage also requires `ELASTIC_STORE_CASES=true`. Historical lookups can use configured Elastic records, but matches remain contextual and never prove fraud.

The event ledger is persisted in SQLite, with a configurable retention period (`WATCHTOWER_RETENTION_DAYS`, default 90 days) that purges expired event evidence automatically. Interrupted `INVESTIGATING` records are re-queued on API startup. Execution is still an in-process, single-instance worker; keep the Render API at one instance and one Uvicorn worker. This is restart-recoverable for the configured deployment, but it is not a horizontally scalable distributed queue. A dedicated external queue and independently scaled workers are still required before claiming high-availability production operation. PayPal's Developer Dashboard webhook simulator does not support postback signature verification; use a real Sandbox app event for the verified-webhook path, or the clearly labelled Watchtower demo simulator to demonstrate automatic agent wake-up.

### Watchtower API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/watchtower/status` | Listener/configuration status and event counts |
| GET | `/api/v1/watchtower/events` | Recent event history |
| GET | `/api/v1/watchtower/events/{event_id}` | One event and its safe public result |
| POST | `/api/v1/watchtower/paypal/register` | Register supported events with the connected PayPal Sandbox app (token required) |
| POST | `/api/v1/watchtower/paypal/webhook` | PayPal signature-verified webhook intake |
| POST | `/api/v1/watchtower/events` | Shared-secret authenticated generic event intake |
| POST | `/api/v1/watchtower/demo/simulate-invoice` | Explicitly simulated invoice event for demos |

Watchtower does not claim to continuously poll a PayPal account. It reacts to webhooks after you register the HTTPS endpoint and configure the webhook ID. PayPal delivers only events associated with the REST app to which that webhook is subscribed; this is not a universal feed of every activity in a person's PayPal account. It does not automatically approve, decline, pay, cancel, or otherwise change transactions.

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
| GET | `/ready` | Configuration readiness checks; no provider API calls are made |
| POST | `/api/v1/investigate` | Complete investigation response |
| POST | `/api/v1/investigate/stream` | Progress events and final result using POST + SSE |
| POST | `/api/v1/evidence/verify` | Verify evidence manifest hashes and root integrity |

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
python -m py_compile schemas.py tools.py elastic_intelligence.py scoring.py agent.py watchtower.py main.py render_dispatch.py render_workflow_tasks.py
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

## Deployment security and operating boundary

- Set `APP_ENV=production`. The Render blueprint does this and restricts CORS to the configured frontend origin.
- Configure a long, random `SCAM_AIRBAG_API_TOKEN` or `WATCHTOWER_INGEST_TOKEN`. Set a separate `EVIDENCE_SIGNING_KEY` if you want evidence receipts signed independently of the API access token; otherwise the service token is used for HMAC signing. The frontend's Service token field sends it only in request headers. Production requests are rate-limited per IP and bounded for request size and concurrent model calls. Do not place it in source code or commit it.
- The current token is a **single-operator shared secret**, not multi-user identity, tenant isolation, or customer account authentication. Do not expose this deployment as a public multi-tenant service.
- The current durable Watchtower runner is restart-recoverable but single-instance and in-process. Run one API instance and one Uvicorn worker; use an external durable queue and independently managed workers before horizontal scaling or high-availability claims.
- Configure persistent disk storage and rotate secrets if they are exposed. Set retention/deletion policies appropriate to your deployment and obtain consent before enabling historical case contribution.
- Keep PayPal Sandbox credentials and event subscriptions separate from Live. This release is an evidence-backed decision-support system; it never executes, approves, declines, cancels, or moves money.
- The evidence manifest's HMAC signature detects report edits unless the signing secret is compromised. It is a ScamAirbag server signature, not a digital signature from PayPal, VirusTotal, WHOIS, or a mail provider. Email headers pasted by a user remain untrusted claims until independently authenticated.
- The app has automated regression coverage, but live PayPal webhook delivery, PayPal API permissions, Render persistent disk behavior, and third-party API quotas must still be verified in the target account before production use.
