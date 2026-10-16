# AGENTS.md

## Scope

Permit is a framework-neutral commercial-entitlement protocol and Racket reference implementation. The default `permit` facade is client-only; issuer operations live under `permit/issuer`. Keep its dependency direction independent: products may use Permit beside Rivet or Glaze; Rivet and Glaze must not depend on Permit. The normative shared boundary is `docs/framework-integration.md`; Rivet and Glaze summarize and link to it instead of restating it, so boundary and trust-domain changes land here first.

The wider family dependency graph, ownership table, change routing, and release
order are maintained in Keel's
[`CONTRIBUTING.md`](https://github.com/turinglambdaai/keel/blob/main/CONTRIBUTING.md#family-operating-model).
Permit's implementation queue remains owned by `ROADMAP.md`; its protocol and
trust domain stay independent from Keel and the application frameworks.

Before changing code, read `docs/architecture.md`. Treat `docs/protocol-v1.md` as normative for wire behavior and this file as the compact implementation checklist.

## Invariants

- Ed25519 signs the exact decoded payload bytes. Never replace this with “parse then canonicalize”.
- Verify the signature and trust key before parsing claims for authorization. The `verified-credential` constructor is intentionally private; never export a public path that lets product code manufacture one. Do not re-export issuer/raw-wire helpers from the default `permit` facade.
- Security-critical fields are strict and fail closed. Duplicate JSON object members are rejected recursively; new vendor data belongs under `extensions`.
- `use_expires_at`, `updates_through`, and `features_through` have independent meanings. Feature grants use explicit `feature_policy` values rather than wildcard IDs.
- `credential_id` identifies one signed statement; `entitlement_id` + monotonic `revision` identify one logical right across reissues. Revision is not revocation.
- Entitlements are long-lived commercial rights; activation credentials are short-lived leases bound to the exact entitlement id/revision/credential snapshot.
- `installation_id` is application-generated and privacy-preserving, not hardware fingerprinting. Local first-run trial state is non-protocol, storage-agnostic, and explicitly not tamper-proof.
- Seat, device, and concurrent limits remain distinct.
- Signing-key time windows constrain authenticated `issued_at`, not client verification wall-clock time; retired keys must preserve valid perpetual credentials.
- Trust stores must not alias one public key under multiple key ids, and each key explicitly limits the credential types it may sign.
- Update-signing keys and Permit credential-signing keys remain separate.

## Boundaries

Do not add payment processing, accounts, email, dashboards, pricing, tax, hosted metering, or a full license server to v0.x. Future management components must issue signed credentials through the protocol boundary.

## Changes

- Update `docs/protocol-v1.md` for every wire-format or normative semantic change.
- Add or update deterministic test vectors for every signing-format change.
- Preserve older vectors unless the protocol version intentionally changes.
- Keep the CLI thin: commands call library operations and do not reimplement schema, trust, or policy rules.
- Add regression tests for every behavior change. Add language-neutral vectors when the behavior could diverge across implementations.
- Use public-facade tests for supported API behavior and module-level tests for internal edge cases.
- Run `raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl`, `raco test -p permit`, vector regeneration with a clean diff, and a clean package install before release.
- Never commit private production key material. Test keys must be clearly marked public and deterministic.

## Handoff standard

Leave the repository understandable without chat history. A completed change includes the relevant code, tests, user-facing documentation, normative text when semantics change, and a concise changelog entry. Do not leave protocol decisions only in comments, issues, or conversation transcripts.

Do not claim compatibility, security, or production readiness from unit tests alone. Record the concrete platforms, Racket versions, vectors, package-install checks, or external implementation evidence actually exercised.
