# Security policy

## Reporting

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue for a suspected vulnerability involving signature verification, credential parsing, trust decisions, or private-key exposure.

## Security model

- Ed25519 private keys remain issuer-only. They must not be committed, embedded in applications, or copied into CI logs.
- Applications embed only a public trust store.
- The signature authenticates the exact payload bytes.
- Core schemas fail closed; duplicate JSON object members are rejected recursively; extensions are the only open namespace.
- Offline credentials cannot learn that a remote refund or revocation occurred. Products requiring timely control must refresh signed state or require short-lived activation leases.
- Local policy enforcement can be patched by an attacker controlling the client. Permit prevents credential forgery; it is not anti-tamper DRM.
- Clock-based expiration assumes a sufficiently trustworthy local clock. High-value managed products should combine short leases with server-observed refresh history.

## Key operations

- Use separate keys for production entitlements, online activation, staging, and application updates. Trust-key `purposes` must match the intended credential types.
- Store production private keys in an OS secure store, HSM, or managed signing system when available.
- Pre-distribute a `next` public key with a future issuance `not_before` before issuing with it.
- Mark a no-longer-used key `retired` with a finite issuance `not_after`; old credentials issued inside that window remain authentic indefinitely.
- Reserve `revoked` for compromise or explicit invalidation. Trust stores must not alias one public key under several key ids.
- A compromised private key requires a trust-store update through the application's authenticated update channel.

## Supported versions

Until a 1.0 release, only the latest `main` branch and latest tagged v0.x release receive security fixes.

## Credential lifecycle

`revision` is replacement metadata among credentials the client has received; it is not a remote revocation primitive. Activation leases bind to an exact entitlement id, revision, credential id, and installation id so a fresh lease cannot silently authorize a stale rights snapshot.
