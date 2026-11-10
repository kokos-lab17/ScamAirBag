# Sponsor technology integration status

This document separates runtime integrations from developer-workflow tools.

| Sponsor | ScamAirbag use | Status |
|---|---|---|
| PayPal | Sandbox invoice, order, and subscription verification | Runtime integration exists |
| AG Grid | Interactive evidence findings explorer with sorting, filtering, pagination, row selection, evidence inspection, and CSV export | Community edition integration enhanced |
| Elastic | Opt-in storage of minimized case indicators and historical exact-domain lookup | Runtime integration exists; credentials required |
| Postman | API collection covering health, JSON investigation, PayPal Sandbox lookup, SSE, and validation checks | Test workflow enhanced |
| Render | FastAPI deployment, static frontend hosting, health checks, optional asynchronous workflow dispatch | Deployment integration exists; environment configuration required |
| APIMatic | PayPal Context Plugin to ground coding-agent work on PayPal API contracts | Developer-time setup; requires local installation and actual use |

## Privacy and evidence boundaries

- Elastic indexing is opt-in and disabled by default. Stored fields are minimized indicators, domains, coarse risk band, and timestamp; raw message text and payment identifiers are not stored.
- Elastic history is the project's own consented case corpus, not a global scam database. An empty result means no matching record in this corpus, not that a domain is safe.
- AG Grid uses Community features. Enterprise-only row grouping, server-side row model, and set-filter features are not claimed.
- Postman tests validate API contracts and response shape. They do not prove a real-world seller or domain is safe.
- APIMatic Context Plugin is a development tool, not a runtime dependency.
- VirusTotal remains optional and is not required for this sponsor-integration phase.

## Local verification

1. Import `postman/ScamAirbag.postman_collection.json` into Postman.
2. Set `baseUrl` to the local API or deployed API.
3. Run Health, Investigate message, Stream investigation, and Validation & safety folders.
4. Only run the PayPal invoice request after setting a real PayPal Sandbox invoice ID.
5. Check the AG Grid controls in the frontend: quick search, severity filter, provenance filter, reset, CSV export, pagination, and selected-row evidence detail.
