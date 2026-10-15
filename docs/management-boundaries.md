# Management boundaries

Permit v0.1 implements the protocol, offline verifier, local policy engine, and issuance CLI. It intentionally does not implement a hosted commercial backend.

## In v0.1

- Credential schema and exact-payload Ed25519 signatures
- Issuer tooling for local/offline issuance
- Entitlement, trial, and activation-lease verification
- Local evaluation of products, bundles, editions, features, add-ons, windows, versions, and installations
- Trust stores and key rotation

## Future management plane

A separate service may eventually manage:

- payment-webhook to entitlement issuance orchestration;
- account/customer lookup and credential delivery;
- seat and device allocation, release, and transfer;
- activation refresh and revocation distribution;
- organization administration and audit history;
- App Store, Microsoft Store, or third-party commerce receipt exchange;
- air-gapped enterprise request/response workflows.

That service should output signed Permit credentials. It must not become a required online oracle for products that promise offline use.

## Explicitly outside Permit

- Checkout, cards, invoices, tax, VAT, refunds, and pricing
- Login, OAuth, password recovery, and user profiles
- Customer dashboards, transactional email, CRM, and support systems
- SaaS metering, hosted API quotas, or LLM usage billing
- Application packaging, code signing, notarization, and update-artifact signing
- Hardware dongle drivers and platform secure-storage implementations

Products choose whether to use Permit. Rivet and Glaze remain application frameworks and do not depend on it.
