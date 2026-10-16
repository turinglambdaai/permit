# Changelog

## Unreleased

### Added

- Add a C conformance runner under `conformance/c/` that executes the
  Protocol v1 vector corpus as an independent non-Racket implementation:
  exact-byte Ed25519 authentication, trust-store rules, closed schemas,
  rejection classes, and policy decisions with exact failure reasons. CI
  builds and runs it on macOS and Linux.
- Add the release checklist used to cut Permit versions, including the
  signed source release procedure.
- Document the Racket API support and deprecation windows in the
  compatibility guide.
- Scribble manual (`permit-doc`): the client verification surface, policy
  evaluation, issuer API, CLI, and local-trial runtime, rendered as the
  package documentation for the catalog.
- Add a maintainer architecture map, contribution contract, roadmap, and ADR template so future work can proceed without relying on conversation history.
- Strengthen CI with manual compilation and byte-for-byte vector reproducibility checks.
- Consolidate every Racket test under `permit-test/` so local and package-level test entry points cover the same suite.
- Expand the deterministic Protocol v1 corpus to cover entitlement, managed activation, signed trial, trial extension, offline grace, and published-through feature decisions.
- Add English and Chinese step-by-step guides that separate issuer secrets, shipped trust data, verification, and product policy evaluation.
- Add an opaque issuer credential predicate and writer so programmatic issuers can safely persist the result of `issue-credential` without importing raw envelope internals.
- Document the durable sibling-library integration contract for products that compose Permit with Rivet or Glaze.
- Add repeatable `raco permit keygen --purpose ...` for least-privilege signing keys while preserving the all-purpose default for small deployments.

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
