# Changelog

## Unreleased

### Fixed

- Close the findings of the first independent security review
  (`docs/security-review-2026-10.md`). The C runner now rejects NUL
  escapes inside JSON strings, integers beyond signed 64-bit (no silent
  clamping), non-finite capability values, and trailing bytes after the
  DER public key; the grace addition saturates instead of overflowing.
  The Racket reference now rejects `\u0000` on the same layer and
  detects aliased trust keys by DER bytes instead of Base64 text, and
  its schema bounds integer fields to signed 64-bit so both
  implementations decide identically. Regression tests pin every finding;
  the normative rules live in `docs/protocol-v1.md`.

### Added

- Add the issuer-side rights-snapshot layer to `permit/issuer`
  (`docs/decisions/0001`): `subject`, `grant`, `constraints`, and
  `entitlement-payload` spell the closed entitlement schema with validation
  at the call site; `successor-payload` is the one supported spelling of a
  new revision in an existing lineage (identity inherited, revision
  advanced, everything else replaceable); `payload->bytes` is the single
  serialization step the exact-byte rule allows. This is the boundary
  Commerce's issuer adapter consumes instead of assembling JSON.
- Type every refusal (`docs/decisions/0002`). `exn:fail:permit` carries a
  `reason`; `verify-credential` raises `exn:fail:permit:verify` with one of
  `verify-failure-reasons` (envelope, key-unknown, key-revoked, signature,
  schema, issuer, key-window, key-purpose — pipeline order, so the reason
  names the guard), and `issue-credential` raises `exn:fail:permit:issue`
  with one of `issue-failure-reasons` (schema, issuer, key-unknown,
  key-status, key-window, key-purpose, key-mismatch). Products translate a
  refused license file by reason instead of matching message text; the CLI
  prints the reason on its own line. Messages and fail-closed behavior are
  unchanged; time outcomes remain `credential-status` reasons.
- Name Commerce as the family commercial-management owner and define the
  one-way `Commerce issuer adapter -> permit/issuer` boundary without moving
  payment, account, delivery, or framework behavior into Permit.
- Add `docs/integration-evidence.md`, the record the v0.2 gate asks for:
  gptp-studio as the first real integration, with its offline startup,
  credential replacement, key rotation, expiry, and corrupt-state
  behavior pinned by tests, plus the problems the integration surfaced.
- Declare `rackunit-lib` as a runtime package dependency because the public
  source package includes the `permit-test` collection.
- Add a C conformance runner under `conformance/c/` that executes the
  Protocol v1 vector corpus as an independent non-Racket implementation:
  exact-byte Ed25519 authentication, trust-store rules, closed schemas,
  rejection classes, and policy decisions with exact failure reasons. CI
  builds and runs it on macOS and Linux.
- Register the package in the public catalog and fix the `license` field
  to a bare SPDX symbol so the catalog recognizes Apache-2.0.
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
