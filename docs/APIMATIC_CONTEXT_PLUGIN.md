# APIMatic PayPal Context Plugin

## Role in ScamAirbag

APIMatic's PayPal Context Plugin is a **developer-time integration assistant**, not a library or service called by ScamAirbag at runtime. It gives the coding agent current PayPal API endpoint, authentication, model, error-handling, resilience, and testing context.

## Install in the development environment

Prerequisite: Node.js 18+. In the VS Code terminal opened at the ScamAirbag repository, run:

```bash
npx context-plugins install paypal
```

The installer detects supported coding assistants and installs the PayPal context plugin. Follow its prompts and confirm the plugin is enabled in the coding assistant. Official listing: https://context.apimatic.io/plugins/paypal/

## Use it for this project

Ask the coding agent to inspect the current PayPal integration before editing it. Focus on:

1. OAuth client-credentials authentication and sandbox/live base URL separation.
2. Invoice retrieval response fields used by `tool_paypal_invoice`.
3. Order retrieval response fields used by `tool_paypal_order`.
4. Subscription retrieval response fields used by `tool_paypal_subscription`.
5. Error mapping, timeouts, retries, and safe logging.
6. Contract tests using PayPal Sandbox responses.

Require the coding agent to cite the plugin-provided endpoint/model context in its explanation and to preserve ScamAirbag's existing `ToolExecutionResult` contract. Verify changes with the Postman collection and local regression tests. Never move PayPal client secrets into frontend code or Postman shared values.

## Accurate sponsor claim

Do not claim APIMatic was integrated into the running application. It is used to ground the development of ScamAirbag's PayPal API integration. Only claim it was used after the plugin has actually been installed and consulted during development.
