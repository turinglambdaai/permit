# Security review — Protocol v1 (first round, 2026-10-16)

Independent adversarial review of the exact-byte signature verification,
strict parsing, trust transitions, lineage selection, and policy
boundaries — the five surfaces the v0.2 gate names. Method: the five
normative documents were read against both implementations, then ~100
adversarial probes (Racket and C harnesses, built outside the tree) were
run against real signed credentials produced from the vector corpus's
RFC 8032 test keys. Baseline at review time: 291 Racket tests, 66 C
runner checks, all green.

## Conclusion

**The core security design holds; no critical or high findings.** The
verification order (envelope shape → key lookup/revoked → signature
before any payload parse, never re-serialized), exact-byte binding,
fail-closed posture, three independent windows, activation four-way
binding, purpose separation, and revoked-overrides-issuance-time are all
effective in both implementations; every forged/bypass/relay attack
constructed during the review was defended.

**However, "the C runner mirrors the Racket reference implementation
exactly" did not hold.** The C runner is more permissive than the
reference in four spots (M1–M4), and the same signed file verifies in C
while Racket rejects it. None of the divergences are forgery paths (they
all sit after signature verification, on values that still come from the
issuer's signed bytes), but they break the two-implementation agreement
evidence the v0.2 gate requires. All four are fixed in this repository
before any v0.2 release.

## Findings and disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| M1 | medium | C runner decodes envelope Base64 fields with `strlen`; an embedded `\u0000` truncates the value so a non-canonical envelope verifies in C (Racket rejects) | fixed — string-level NUL rejection plus explicit-length decode |
| M2 | medium | C `strtoll` ignores `ERANGE`; integers beyond int64 are silently clamped, flipping an activation-lease binding decision against Racket's exact bignums | fixed — out-of-range integers are rejected |
| M3 | medium/low | C accepts `+inf` as a capability value (`1e999`); Racket's `rational?` rejects it | fixed — non-finite reals rejected |
| M4 | medium/low | C matches JSON member names with `strcmp`, so a `"type\u0000"` key aliases the schema field | fixed — NUL rejected in member names at parse time |
| L1 | low | Racket strict JSON reader accepts a bare literal token with trailing garbage (`123x` → `123`); currently unreachable because every consumer requires an object root | known, watch: reachable only if a non-object root is ever accepted |
| L2 | low | C ignored trailing bytes after the DER public key; Racket rejects | fixed — decoder must consume exactly `der_len` bytes |
| L3 | low | Racket trust-store aliasing compares Base64 text, relying on canonical-encoding premises; C compares raw 32 bytes | fixed — Racket compares decoded key bytes, matching C |
| I1 | informational | Racket accepts NUL inside key ids, C rejects the store | fixed — control characters rejected in key ids on both sides |
| I2 | informational | C grace addition can overflow signed long long (UB, fail-closed direction) | fixed — saturation instead of wrap |
| I3 | informational | all C string comparisons truncate at NUL | fixed with M1/M4 (explicit-length / NUL-free strings) |
| I4 | informational | the C runner covers usable/feature/update/version queries but not lineage selection or capability/limit queries | tracked for the conformance-runner scope, not a defect in what it does cover |
| I5 | informational | CLI `sign` is the documented issuance-policy escape hatch; verification still enforces everything | accepted by design; no verifier-side bypass exists |
| I6 | informational | the probe shapes above were not covered by vectors | folded into the regression vectors for the fixes |

## Verified defended (evidence per surface)

- **Exact-byte verification**: field swap/length confusion, URL-safe
  alphabet, embedded whitespace, missing/extra/uneven padding, empty
  payload, single-byte append to signed payload, real key under foreign
  id, trailing JSON value/BOM — rejected on both sides.
- **Strict parsing**: recursive duplicate keys (including `\u0061`
  escape spellings and nested grants/capabilities/extensions), depth 64
  accepted / 65 rejected, type confusion (revision as string/float/-1,
  version as 1.0/"1"), lone surrogates rejected, valid surrogate pairs
  decoded, invalid UTF-8/BOM/bare control characters rejected, calendar
  impossibilities (Feb 30, hour 24, second 60, lowercase t/z, offsets)
  rejected on both sides; year 0000/9999 and leap days accepted
  consistently.
- **Trust transitions**: revoked keys reject regardless of issuance
  time; purpose separation enforced both directions; `next` requires
  `not_before`, `retired` requires `not_after`, endpoints inclusive;
  issuance windows constrain `issued_at`, not verification wall-clock;
  same-key-under-two-ids rejected.
- **Lineage selection**: highest revision wins; equal-revision
  different-bytes fails closed; byte-identical duplicates tolerated;
  cross-issuer mixing rejected; activation binding rejects wrong
  installation, wrong revision snapshot, wrong entitlement id, wrong
  issuer.
- **Policy boundaries**: the three windows are independent; `*` in
  `features` rejected by schema; expiry/not-yet-valid/installation
  mismatch/missing activation travel as status reasons, never
  exceptions, never grants; version policy fails closed without its
  context; trial extensions are idempotent; local trial high-water mark
  never regresses.

## Cross-implementation agreement

Agreed (verified point by point): verification pipeline order and error
classes, canonical Base64, recursive duplicate-key rejection and depth
limit, JSON string/UTF-8/escape rules (modulo the NUL findings), the
full RFC 3339 calendar matrix (both sides compare string ordinally),
SemVer 2.0 precedence, closed schema field sets, three-window endpoint
semantics, activation binding and grace endpoints, purpose/status state
machines, revoked-overrides-issuance-time, issuance windows constrain
`issued_at` only.

Diverged: the M1–M4 permissiveness on the C side, L2 DER trailing
bytes, I1 NUL key ids (Racket side), I3 NUL string comparison. All
fixed; the agreement claim now holds again.
