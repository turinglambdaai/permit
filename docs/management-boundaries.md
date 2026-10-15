# Management boundaries

Permit v0.1 implements the protocol, offline verifier, local policy engine, and issuance CLI. It intentionally does not implement a hosted commercial backend.

## In v0.1

- Credential schema and exact-payload Ed25519 signatures
- Issuer tooling for local/offline issuance
- Entitlement, signed trial, signed trial-extension, and activation-lease verification
- Local evaluation of products, bundles, editions, features, add-ons, windows, versions, and installations
- Trust stores, issuance-window key rotation, entitlement lineage, and revision selection

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

## Replacement versus revocation

A newer entitlement revision replaces an older revision only among credentials a client has actually received. It does not make hidden offline copies disappear. Products requiring timely downgrade, refund revocation, or seat reclamation must opt into a management mechanism such as short-lived activation leases or future signed revocation state.
