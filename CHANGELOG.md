# Changelog

## Unreleased

### Protocol v1 hardening

- Separate logical `entitlement_id` from unique signed `credential_id` and add monotonic revisions.
- Bind activation leases to an exact entitlement id, revision, credential id, and installation id.
- Add replay-safe signed trial-extension credentials.
- Make key validity windows constrain authenticated issuance time so retired keys do not expire perpetual rights.
- Harden SemVer, Base64, trust-store aliases, scalar capability conflicts, and strict JSON parsing.
- Add add-on and standard-limit policy queries plus split normative protocol documentation.

## 0.1.0 - 2026-10-15

- Define Permit Protocol v1 with exact-payload Ed25519 envelopes.
- Add entitlement, signed trial, and activation-lease schemas.
- Add grants, bundles, capability limits, independent commercial windows, installation binding, and version policy.
- Add trust stores with key rotation and revocation states.
- Add the Racket reference API and `raco permit` CLI.
- Add deterministic cross-language test vectors and cross-platform CI.
