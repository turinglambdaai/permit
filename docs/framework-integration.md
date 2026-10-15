# Framework integration

Permit is a sibling of an application framework, not a framework subsystem.
An application may depend on both; Rivet and Glaze do not depend on Permit.

```text
                         Product
                       /         \
              Rivet or Glaze     Permit
              runtime / update   product rights
```

## Responsibility boundary

| Owner | Responsibilities |
| --- | --- |
| Product | Feature names, editions, commercial policy, authorization UI, credential refresh timing, and the decision to run fully offline or require activation leases |
| Permit | Signed credential format, trust-store verification, entitlement/trial/activation semantics, policy evaluation, privacy-preserving installation identifiers, and local-trial state |
| Rivet or Glaze | Application lifecycle, native UI, packaging, platform secure-storage primitives, distribution, and update-artifact verification |
| Future management plane | Payment/account integration, seat allocation, device reclamation, subscription renewal, recovery, and issuing refreshed Permit credentials |

This direction is intentional:

```text
product -> framework
product -> Permit

framework -X-> Permit
Permit    -X-> framework
```

No adapter is required for normal use. Product code imports the framework and
Permit independently:

```racket
#lang racket/base

(require permit
         glaze/core) ; or the Rivet modules used by the product

(define trust-store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" trust-store))

(when (feature-entitled? entitlement "example-product" "pro-feature")
  (enable-pro-feature!))
```

The framework may provide a general secure-storage service. The product may
use it to store a Permit credential, local-trial state, or `installation_id`,
but the storage API remains general-purpose and Permit remains storage-agnostic.
Do not add entitlement, trial, activation, payment, or account policy to the
framework to make this composition work.

## Separate trust domains

The following keys are not interchangeable:

- Permit credential-signing keys authenticate commercial rights.
- Update-manifest or update-artifact keys authenticate software releases.
- Platform publisher credentials authenticate OS packages and applications.

Compromise, rotation, or retirement in one trust domain must not silently
change another. Products should use distinct keys, identifiers, storage, and
operational procedures for each domain.

## Framework maintenance rule

Rivet and Glaze may document Permit as an optional product-layer companion,
but must not add a package dependency on it or recreate a built-in licensing
subsystem. If a product later needs convenience glue, keep that code in the
product or a separately versioned adapter so framework users who do not sell
commercial software inherit no policy or dependency.
