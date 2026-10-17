# 0002: Typed verification failures on the client facade

- Status: accepted
- Date: 2026-10-17

## Context

`verify-credential` refuses a credential with an ordinary
`exn:fail:contract` from whichever layer noticed first: `read-envelope`
(envelope shape, Base64), `trust-store-key` (unknown or revoked key),
the signature check, `parse-credential-payload` (schema), the issuer
comparison, and the key window and purpose guards. A product that must show
the customer *why* a license file was refused — and every product in the
family will, since Permit is the family's licensing layer — can only match
message text. gptp-studio's adapter does exactly that today
(`string-contains?` on five substrings, everything else collapsing to
"malformed"), which degrades silently the moment a message changes.

Decision 0001 gave the issuer side `exn:fail:permit:issue` with a `reason`.
The verifier side is the half products actually embed, so it needs the same
treatment, and the two should share one parent so a product can catch "any
Permit refusal" in one clause.

Time-based outcomes are not failures: expiry, not-yet-valid, installation
mismatch, and missing activation already travel as `credential-status`
reasons, never as exceptions. That split stays.

## Decision

`permit/failure.rkt` defines the family:

- `exn:fail:permit` with a `reason` symbol, the parent;
- `exn:fail:permit:verify`, raised by `verify-credential`;
- `exn:fail:permit:issue`, raised by `issue-credential` (decision 0001),
  re-based onto the parent.

`verify-failure-reasons` names the verifier reasons in pipeline order:
`envelope` (the wrapper could not be read or is not a Protocol v1
envelope), `key-unknown`, `key-revoked`, `signature`, `schema` (the
authenticated payload failed strict parsing or schema validation),
`issuer`, `key-window`, `key-purpose`. The pipeline order is the order a
conforming verifier must check in, so the reason also tells a reader which
guard refused.

Messages keep their current text and `raise-arguments-error` layout so
message-matching tests and adapters keep working; the reason is additive.
Fail-closed behavior is unchanged: a refusal is still an exception, never a
return value. Argument-shape errors (a store that is not a `trust-store?`)
stay plain contract errors — they are programmer mistakes, not refusals.

The default `permit` facade exports `exn:fail:permit`,
`exn:fail:permit:verify`, and `verify-failure-reasons`. The CLI's top-level
handler prints the reason on its own line after the message so scripts can
read it without parsing text.

## Consequences

- Product adapters map a refusal to a customer-facing message by reason;
  the message text becomes free to improve.
- `verify-credential` performs its guards inline (key lookup, revoked,
  window, purpose) instead of delegating to helpers that raise, so each
  refusal is attributed at the point the pipeline notices it. The helpers
  (`trust-store-key`, `trust-key-authorize-*!`) remain for other callers.
- Cost: one more module and two struct types in the public surface; the
  documentation and API tests pin them.
- Rejected: a single reason namespace shared by issue and verify (the
  pipelines differ — `key-status` on the issuer side means "not active",
  on the verifier side only `revoked` refuses); returning a result struct
  instead of raising (breaks the fail-closed discipline every caller relies
  on); mapping expiry into exceptions (time outcomes are status, by
  design).

## Required repository changes

- `permit/failure.rkt` (new); `permit/issuer.rkt` and
  `permit/credential.rkt` raise from it; `permit/main.rkt` exports the
  verify side; `permit/cli.rkt` prints the reason.
- `permit-test/core-test.rkt`: one case per verify reason plus the shared
  parent catch.
- `permit-doc/scribblings/permit.scrbl`: a failures subsection under
  "Verifying credentials"; the issuer subsection points at the parent.
- `CHANGELOG.md`.
