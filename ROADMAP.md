# Roadmap

Permit develops from a small, audited core outward. Milestones describe readiness, not promised dates.

## v0.1 — protocol and reference core (complete)

- Protocol v1 envelope, credential schemas, trust model, and policy semantics
- client-only Racket facade and opt-in issuer API
- entitlement, trial, trial-extension, and activation credentials
- perpetual, maintenance-window, feature-window, subscription, team, seat, bundle, and installation models
- local first-run trial helper with explicit limitations
- CLI, deterministic conformance vectors, multi-platform CI, product site, and newcomer documentation

The v0.1 line intentionally excludes payment, accounts, dashboards, email delivery, hosted metering, and a license server.

## Current gate — earn v0.2

Permit does not reach v0.2 by adding more credential types. It reaches v0.2
when the existing protocol has independent review and product evidence:

1. Complete an independent security-focused review of exact-byte signature
   verification, strict parsing, trust transitions, lineage selection, and
   policy boundaries. Close every critical/high finding before release.
2. Integrate the public client facade in at least one real Rivet or Glaze
   product without adding a framework dependency. Record offline startup,
   credential replacement, key rotation, expiry, and corrupt-state behavior.
3. Turn problems found by that integration into framework-neutral diagnostics
   or API corrections, with regression tests and compatibility notes.
4. Cut a signed release only after the package-install, documentation, vector,
   Racket, and independent C conformance gates all pass from the release tag.

Already complete: the C runner exercises Protocol v1 independently of Racket;
the release checklist defines signed source releases; and the compatibility
guide defines Racket API support and deprecation windows.

## Allowed v0.2 scope

- structured diagnostics that preserve fail-closed behavior;
- narrowly scoped client helpers proven by product integration and independent
  of Rivet and Glaze;
- conformance-runner ergonomics that make additional implementations easier;
- issuer-boundary definitions needed by Commerce for allocation, renewal,
  recovery, and credential delivery, without implementing those workflows,
  accounts, or billing here.

Higher-level adapters wait until at least two products need the same portable
meaning. These candidates require design review before implementation and must
not move payment or account logic into the protocol core.

## Toward 1.0

Permit reaches 1.0 only after Protocol v1 has multiple production integrations, cross-language verification evidence, a security review, and a clearly documented stable Racket API. Compatibility is earned through evidence rather than declared from code coverage alone.
