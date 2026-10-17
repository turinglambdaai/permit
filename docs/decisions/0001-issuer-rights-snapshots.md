# 0001: Issuer-side rights snapshots and typed issuance failures

- Status: accepted
- Date: 2026-10-16

## Context

Commerce's next slice ("Offer-to-Permit policy mapping", then "Permit
credential issuance") needs to construct a complete rights snapshot and hand
it to `permit/issuer`. Today `issue-credential` accepts only payload bytes.
Every caller therefore assembles the closed entitlement schema by hand: the
reference tests do (`entitlement`/`constraints`/`default-grant` helpers in
`permit-test/core-test.rkt`), gptp-studio's gate tests do, and Commerce
would be the third copy. A closed schema that three consumers spell out
independently drifts the first time Permit adds or renames a field, and the
failure shows up at signing time as an opaque contract error.

Issuance failures are also untyped: every guard raises
`exn:fail:contract` with a different message, so an adapter that must record
why issuance was refused (schema, foreign issuer, retired key, issuance
window, key purpose, key mismatch) has to match message text. The v0.2 scope
allows "structured diagnostics that preserve fail-closed behavior" and
"issuer-boundary definitions needed by Commerce for allocation, renewal,
recovery, and credential delivery, without implementing those workflows".

Two boundaries constrain the design. The exact-byte rule: the issuer signs
the payload bytes it is given and nothing may re-serialize them afterwards.
The dependency rule: Permit never depends on Commerce, and the default
`permit` facade never exports issuer tools.

## Decision

`permit/issuer` gains a rights-snapshot layer and a typed failure.

**Constructors** produce validated jsexprs; every schema field is an explicit
keyword with a `'null`/empty default where the schema allows one, so there is
no way to omit a field by accident:

- `(subject #:type #:id [#:display])`
- `(grant #:products #:product-families #:edition #:feature-policy #:features #:addons #:capabilities)`
- `(constraints #:use-expires-at #:updates-through #:features-through #:version-min #:version-max #:named-seats #:device-activations #:concurrent-seats #:installation-id #:activation-required?)`
- `(entitlement-payload #:type #:issuer #:credential-id #:entitlement-id #:revision #:subject #:channel #:grants #:constraints #:issued-at #:not-before #:extensions)`

`entitlement-payload` runs `validate-credential-claims` before returning, so
constructing an invalid snapshot fails at the call site with the schema
error, not later inside the signer.

**Lineage**: `(successor-payload previous #:credential-id #:issued-at ...)`
builds the next revision of an existing entitlement: `entitlement_id`,
`issuer`, and `type` are inherited and cannot be overridden, `revision` is
`previous + 1`, `subject`/`channel`/`grants`/`constraints`/`extensions`
default to the previous values and may be replaced, `not_before` defaults to
`'null`. This is the only supported way to spell "renewal, upgrade,
downgrade, seat change, or withdrawal issue a complete new revision in the
same lineage". A withdrawal is a successor whose constraints already expired.

**Bytes**: `(payload->bytes jsexpr)` serializes once. Callers store and sign
those bytes; the protocol's never-re-serialize rule now has a named step on
the issuer side too.

**Typed failure**: `issue-credential` raises `exn:fail:permit:issue` with a
`reason` symbol — `schema`, `issuer`, `key-unknown`, `key-status`,
`key-window`, `key-purpose`, or `key-mismatch`. Messages keep the existing
`name: message / field: value` layout so message-matching tests still pass;
the reason is additive. Fail-closed behavior is unchanged: every refusal is
still an exception, never a return value.

**Out of scope for this record**: activation and trial-extension
constructors (wait for Commerce M3 "activation lease refresh"), typed
failures on the verifier side (`verify-credential` still raises contract
errors; a follow-up record covers the client facade), any delivery, claim,
account, or subject-identity behavior, and any default `permit` facade
export of these tools.

## Consequences

- Commerce's issuer adapter and the gptp-studio gate tests stop spelling
  the schema; Permit can evolve field sets with one change and compile-time
  keyword errors at the callers.
- Successor payloads make revision monotonicity and lineage inheritance a
  library invariant instead of adapter discipline.
- Adapters can record issuance refusals by reason without parsing text.
- Cost: `permit/issuer` grows a constructor surface that must track the
  schema; the documentation test and the examples test pin it.
- Rejected: accepting a jsexpr in `issue-credential` directly (would blur
  the exact-byte boundary and invite re-serialization); returning failures
  as values (breaks the fail-closed exception discipline the verifier
  shares); putting constructors in the default facade (products do not
  construct payloads).
- Evidence still required: Commerce's first adapter using these
  constructors end to end, recorded in `docs/integration-evidence.md`.

## Required repository changes

- `permit/snapshot.rkt` (new): constructors, successor, bytes.
- `permit/issuer.rkt`: re-export the snapshot layer; typed
  `exn:fail:permit:issue`; guards raise it.
- `permit-test/issuer-test.rkt`: constructor validation, successor
  inheritance and override rules, each failure reason.
- `permit-doc/scribblings/permit.scrbl`: document every new export.
- `docs/entitlement-v1.md`: point lineage prose at `successor-payload`.
- `CHANGELOG.md`.
