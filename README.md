# Permit

**Signed entitlements for independent software.**

Human-friendly. Offline-first. No account required. No phone-home. Cryptographically signed.

Permit is a framework-neutral protocol and Racket reference implementation for answering one question:

> What may this person, organization, or installation use right now?

It is deliberately not payment processing, an account system, a customer dashboard, or a license server. Commerce systems may issue or refresh Permit credentials later; applications can verify those credentials locally with only an embedded public trust store.

## What v0.1 includes

- Permit Protocol v1 and its exact-payload Ed25519 envelope
- Signed `entitlement`, `trial`, and `activation` credentials
- Offline verification with a multi-key trust store and rotation states
- Grants for editions, features, add-ons, bundles, and scalar capabilities
- Separate use, update-maintenance, and new-feature time windows
- Optional version bounds, installation binding, named/device/concurrent limits
- Short-lived activation leases with an explicit offline grace period
- A Racket library and `raco permit` CLI
- Deterministic cross-language test vectors

The same model expresses:

| Model | `use_expires_at` | `updates_through` | `features_through` |
| --- | --- | --- | --- |
| Perpetual purchase | `null` | `null` | `null` |
| Surge Mac-style maintenance | `null` | maintenance end | `null` |
| Surge iOS-style new features | `null` | `null` | feature window end |
| Subscription | subscription end | as required | as required |
| Trial | trial end | policy-defined | policy-defined |

Team seats, device activations, and concurrent seats are distinct claims. Permit v0.1 validates and exposes them, but a future management service allocates or reclaims them.

## Protocol shape

A credential is an envelope:

```json
{
  "permit_version": 1,
  "algorithm": "Ed25519",
  "key_id": "license-2026",
  "payload": "<base64 of the exact JSON bytes>",
  "signature": "<base64 Ed25519 signature>"
}
```

The signature covers the decoded `payload` bytes exactly. A verifier does not parse and re-serialize JSON before checking the signature. This avoids canonicalization ambiguity across languages.

See [Protocol v1](docs/protocol-v1.md) for the normative schema and [management boundaries](docs/management-boundaries.md) for what intentionally remains outside v0.1.

## Install and test

```sh
raco pkg install --auto --name permit https://github.com/turinglambdaai/permit.git
raco test -p permit
```

For a checkout:

```sh
raco pkg install --auto --no-docs --name permit .
raco test -p permit
```

## CLI

Generate an Ed25519 key pair and a starter trust store:

```sh
raco permit keygen \
  --private private-key.der \
  --public public-key.der \
  --trust-store trust-store.json \
  --key-id license-2026 \
  --issuer com.example
```

Keep the private key out of source control and application bundles. Sign an exact payload file:

```sh
raco permit sign \
  --key private-key.der \
  --key-id license-2026 \
  --payload entitlement.json \
  --output entitlement.permit.json
```

Verify cryptography, the trust key, issuer, and schema:

```sh
raco permit verify \
  --trust-store trust-store.json \
  --credential entitlement.permit.json
```

Evaluate application policy:

```sh
raco permit check \
  --trust-store trust-store.json \
  --credential entitlement.permit.json \
  --product gptp-studio \
  --feature pcap-export \
  --feature-published-at 2026-10-01T00:00:00Z \
  --version 2.0.0
```

`inspect` is intentionally marked unverified. Never authorize a feature from inspected claims alone.

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

An online-managed product verifies both long-lived commercial rights and a short-lived installation lease:

```racket
(credential-usable? entitlement
                    #:installation-id installation-id
                    #:activation activation-lease)
```

Offline products omit the activation layer entirely.

## Architecture

Permit composes beside an application framework:

```text
             Product
            /       \
   Rivet or Glaze   Permit
   runtime/update   commercial rights
```

Rivet and Glaze do not depend on Permit. A product opts into both. Update artifact signing and product entitlements also remain separate keys and responsibilities.

## Status

Protocol v1 is implemented for the v0.1 credential types, but the repository has not yet declared a stable 1.0 compatibility promise. Security-sensitive core fields fail closed; only `extensions` is open-ended.

Licensed under Apache-2.0.
