# APIMatic Context Plugin (developer workflow)

APIMatic's hackathon resource describes its PayPal Context Plugin as a tool for
AI coding assistants. It supplies PayPal API context while a developer builds
an integration; it is **not a runtime dependency of ScamAirbag**.

To use it during future PayPal API changes:

1. Open the APIMatic Context Plugin resource linked from the PayPal AI Hackathon
   APIMatic sponsor page.
2. Follow APIMatic's current setup instructions for your supported coding agent.
3. Ask the coding agent to inspect the PayPal Invoice, Orders, and Subscriptions
   contracts before changing `tools.py`.
4. Verify every generated field mapping against a real PayPal Sandbox response
   and the official PayPal API reference.
5. Record which endpoints and contract details were consulted in the project
   development notes.

Do not claim APIMatic was used unless the Context Plugin was actually connected
and used during development. This repository includes this guide as a setup
note, not as evidence that the plugin has already been used.
