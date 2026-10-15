# AGENTS.md

## Scope

Permit is a framework-neutral commercial-entitlement protocol and Racket reference implementation. Keep its dependency direction independent: products may use Permit beside Rivet or Glaze; Rivet and Glaze must not depend on Permit.

## Invariants

- Ed25519 signs the exact decoded payload bytes. Never replace this with “parse then canonicalize”.
- Verify the signature and trust key before parsing claims for authorization.
- Security-critical fields are strict and fail closed. New vendor data belongs under `extensions`.
- `use_expires_at`, `updates_through`, and `features_through` have independent meanings.
- Entitlements are long-lived commercial rights; activation credentials are short-lived installation leases.
- `installation_id` is application-generated and privacy-preserving, not hardware fingerprinting.
- Seat, device, and concurrent limits remain distinct.
- Update-signing keys and Permit credential-signing keys remain separate.

## Boundaries

Do not add payment processing, accounts, email, dashboards, pricing, tax, hosted metering, or a full license server to v0.x. Future management components must issue signed credentials through the protocol boundary.

## Changes

- Update `docs/protocol-v1.md` for every wire-format or normative semantic change.
- Add or update deterministic test vectors for every signing-format change.
- Preserve older vectors unless the protocol version intentionally changes.
- Run `raco make permit/main.rkt permit/cli.rkt`, `raco test tests/`, and a clean package install before release.
- Never commit private production key material. Test keys must be clearly marked public and deterministic.
