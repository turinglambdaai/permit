# Changelog

## Unreleased

### Added

- Split the Racket API into a curated client facade and explicit `permit/issuer` signing surface.
- Add guarded `issue-credential` checks for issuer, key status/purpose/window, and private/public key correspondence.
- Add privacy-preserving random installation/trial identifiers.
- Add a storage-agnostic local trial state machine with clock high-water tracking and signed trial-extension support.

### Security

- Seal the `verified-credential` constructor so product policy can only receive credentials produced by signature verification.

### Protocol v1 hardening

- Separate logical `entitlement_id` from unique signed `credential_id` and add monotonic revisions.
- Bind activation leases to an exact entitlement id, revision, credential id, and installation id.
- Add replay-safe signed trial-extension credentials.
- Make key validity windows constrain authenticated issuance time so retired keys do not expire perpetual rights.
- Harden SemVer, Base64, recursive duplicate-key JSON rejection, trust-store aliases, per-key credential purposes, scalar capability conflicts, and strict JSON parsing.
- Add explicit vs published-through feature grant modes, add-on and standard-limit policy queries, plus split normative protocol documentation.

## 0.1.0 - 2026-10-15

- Define Permit Protocol v1 with exact-payload Ed25519 envelopes.
- Add entitlement, signed trial, and activation-lease schemas.
- Add grants, bundles, capability limits, independent commercial windows, installation binding, and version policy.
- Add trust stores with key rotation and revocation states.
- Add the Racket reference API and `raco permit` CLI.
- Add deterministic cross-language test vectors and cross-platform CI.
