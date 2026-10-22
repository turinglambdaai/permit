# AGENTS.md

## Scope

Permit is a framework-neutral commercial-entitlement protocol and Racket reference implementation. The default `permit` facade is client-only; issuer operations live under `permit/issuer`. Keep its dependency direction independent: products may use Permit beside Rivet or Glaze, and Commerce may consume `permit/issuer` only through an explicit issuer adapter. Rivet, Glaze, and Permit never depend on Commerce; Rivet and Glaze never depend on Permit. The normative local boundary is `docs/framework-integration.md`; sibling repositories summarize and link to it instead of restating it, so rights and trust-domain changes land here first.

The five-repository dependency graph, ownership table, change routing, release
order, and trust boundaries are maintained in Keel's
[`docs/family-architecture.md`](https://github.com/turinglambdaai/keel/blob/main/docs/family-architecture.md).
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

Do not add payment processing, accounts, email, dashboards, pricing, tax, hosted metering, or a full license server to Permit. Commerce owns provider-neutral commercial orchestration and must issue signed credentials through the `permit/issuer` boundary; it must not move that workflow into this repository.

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

## 组合定位（Portfolio placement）

- 轨道与授权：基础设施（签名授权协议层）；授权形态：Apache-2.0；商业归属：全开源。
- 组合归属唯一权威：[PORTFOLIO.md](https://github.com/turinglambdaai/turinglambdaai.github.io/blob/master/PORTFOLIO.md)（turinglambdaai.github.io 仓库）。改归属/授权先改权威档，再同步本节。
- 纪律：价格只进本仓 `PRICING.md`，且收费开始时才发布；README 与产品站不做价格预告。
