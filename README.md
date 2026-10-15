# Permit

**Signed product rights for independent software — verifiable offline, manageable online when you need it.**

[![CI](https://github.com/turinglambdaai/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/permit/actions/workflows/ci.yml) ![Racket](https://img.shields.io/badge/Racket-9F1D20?logo=racket&logoColor=white) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) ![Protocol](https://img.shields.io/badge/protocol-v1-3559E0)

**English** · [中文](README.zh-CN.md) · [Website](https://permit.jrtx.site)

Permit is a framework-neutral protocol and Racket reference implementation for answering one product question:

> What may this person, organization, or installation use right now?

Payment providers can tell you that money moved. Account systems can tell you who signed in. Permit turns durable product rights into signed, portable credentials that an application can verify locally with an embedded public trust store — without requiring an account, a network round trip, or a framework-owned licensing subsystem.

## Why Permit?

Commercial applications need two properties that are often treated as opposites:

- **Offline-verifiable** — the installed application can authorize features without phoning home.
- **Online-manageable** — a future issuer may renew subscriptions, allocate seats, rotate keys, or refresh short-lived activation leases without changing the verification protocol.

Permit separates those concerns. Long-lived **entitlements** describe commercial rights, optional **activation leases** bind a right to an installation for a limited period, and **trials** remain their own credential type. Products opt into only the layers they need.

Permit composes beside an application framework:

```text
                         Product
                       /         \
              Rivet or Glaze     Permit
              runtime / update   product rights
```

Rivet and Glaze do not depend on Permit. Update-artifact signing and Permit credential signing also use separate keys and trust policies.

## What it models

One Protocol v1 vocabulary covers the common commercial shapes without baking pricing or payment policy into the app:

| Product model | Right to use | Updates | Newly published features |
| --- | --- | --- | --- |
| Perpetual purchase | no expiry | unrestricted or bounded | unrestricted or bounded |
| Surge Mac-style maintenance | perpetual | through maintenance date | normally unrestricted |
| Surge iOS-style feature window | perpetual | normally unrestricted | through feature-window date |
| Subscription | through subscription date | policy-defined | policy-defined |
| Trial | through trial date | policy-defined | policy-defined |

Grants may name editions, features, add-ons, bundles, and scalar capabilities. Team ownership, named seats, device activations, and concurrent seats are distinct claims rather than one overloaded counter. `installation_id` is an application-generated, privacy-preserving identifier — not a hardware fingerprint.

## Quick start

Install the Racket package:

```bash
raco pkg install --auto --name permit https://github.com/turinglambdaai/permit.git
```

Generate an Ed25519 key pair and starter trust store:

```bash
raco permit keygen \
  --private private-key.der \
  --public public-key.der \
  --trust-store trust-store.json \
  --key-id license-2026 \
  --issuer com.example
```

Keep the private key out of source control and application bundles. Sign the exact bytes of a payload file:

```bash
raco permit sign \
  --key private-key.der \
  --key-id license-2026 \
  --payload entitlement.json \
  --output entitlement.permit.json
```

Verify the signature, trust key, issuer, and schema:

```bash
raco permit verify \
  --trust-store trust-store.json \
  --credential entitlement.permit.json
```

Then evaluate product policy:

```bash
raco permit check \
  --trust-store trust-store.json \
  --credential entitlement.permit.json \
  --product gptp-studio \
  --feature pcap-export \
  --feature-published-at 2026-10-01T00:00:00Z \
  --version 2.0.0
```

`inspect` is deliberately labelled unverified. Never authorize a feature from inspected claims alone.

## Protocol v1

A credential is a small JSON envelope:

```json
{
  "permit_version": 1,
  "algorithm": "Ed25519",
  "key_id": "license-2026",
  "payload": "<base64 of the exact JSON bytes>",
  "signature": "<base64 Ed25519 signature>"
}
```

Ed25519 signs the decoded `payload` bytes **exactly**. A verifier checks the signature before parsing authorization claims and never parses then re-serializes the JSON for verification. That rule avoids cross-language canonicalization ambiguity.

Protocol v1 includes:

- `entitlement`, `trial`, and `activation` credentials
- independent `use_expires_at`, `updates_through`, and `features_through` windows
- optional product-version bounds and installation binding
- edition, feature, add-on, bundle, and scalar-capability grants
- team, named-seat, device, and concurrent-seat limits
- short-lived activation leases with an explicit offline grace period
- multi-key trust stores with `next`, `active`, `retired`, and `revoked` states
- deterministic cross-language test vectors

Read the [normative Protocol v1 specification](docs/protocol-v1.md) and the [management boundary](docs/management-boundaries.md).

## Racket API

```racket
#lang racket/base

(require permit)

(define store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" store))

(when (feature-entitled? entitlement
                         "gptp-studio"
                         "pcap-export"
                         #:published-at "2026-10-01T00:00:00Z")
  (enable-pcap-export!))
```

An online-managed product verifies both the durable right and a short-lived installation lease:

```racket
(credential-usable? entitlement
                    #:installation-id installation-id
                    #:activation activation-lease)
```

An offline product omits the activation layer entirely.

## Trust and rotation

Applications ship only public keys. A trust store can stage a `next` key before an issuer starts signing with it, keep an `active` key for normal issuance, retain a `retired` key for credentials issued before a cutoff, and reject a `revoked` key immediately. Issuer constraints and validity windows are checked together with the cryptographic signature.

This lets a release carry tomorrow's public key before the issuing service switches over, while preserving a deterministic offline verification path.

## Deliberate boundary

Permit v0.1 does **not** implement payment processing, customer accounts, email, pricing, tax, a dashboard, hosted metering, or a license server. Those systems may issue and refresh Permit credentials later; they do not belong in the verification core.

Seat allocation, device reclamation, subscription renewal, and account recovery are future management operations. The v0.1 boundary defines the signed artifacts those systems exchange with products.

## Development

```bash
raco pkg install --auto --no-docs --name permit .
raco make permit/main.rkt permit/cli.rkt
raco test tests/
```

The deterministic corpus under [`test-vectors/v1`](test-vectors/v1) is the interoperability contract for other language implementations.

## Repository structure

```text
permit/
├── permit/                 # envelope, schema, policy, trust and CLI modules
├── docs/                   # normative protocol and management boundary
├── test-vectors/v1/        # deterministic cross-language corpus
├── tests/                  # unit, policy and vector tests
└── site/                   # bilingual product homepage
```

## Status

Protocol v1 is implemented for the v0.1 credential types, but the repository has not declared a stable 1.0 compatibility promise. Security-sensitive fields fail closed; only `extensions` is open-ended.

## License

[Apache-2.0](LICENSE)
