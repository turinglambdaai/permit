# Roadmap

Permit develops from a small, audited core outward. Milestones describe readiness, not promised dates.

## v0.1 — protocol and reference core

- Protocol v1 envelope, credential schemas, trust model, and policy semantics
- client-only Racket facade and opt-in issuer API
- entitlement, trial, trial-extension, and activation credentials
- perpetual, maintenance-window, feature-window, subscription, team, seat, bundle, and installation models
- local first-run trial helper with explicit limitations
- CLI, deterministic conformance vectors, multi-platform CI, product site, and newcomer documentation

The v0.1 line intentionally excludes payment, accounts, dashboards, email delivery, hosted metering, and a license server.

## Before v0.2

- complete an independent security-focused review of parsing, trust transitions, and policy boundaries
- exercise the vectors from at least one non-Racket implementation
- collect integration feedback from real desktop applications
- establish a release checklist and publish signed source releases
- document deprecation and support windows for the Racket API

## Candidate v0.2 work

- higher-level application adapter helpers that remain framework-neutral
- management-plane interface definitions for allocation, renewal, recovery, and credential delivery
- additional conformance runner ergonomics for other languages
- structured diagnostics that do not weaken fail-closed behavior

These candidates require design review before implementation. They must not move payment or account logic into the protocol core.

## Toward 1.0

Permit reaches 1.0 only after Protocol v1 has multiple production integrations, cross-language verification evidence, a security review, and a clearly documented stable Racket API. Compatibility is earned through evidence rather than declared from code coverage alone.
