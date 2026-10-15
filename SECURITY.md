# Security policy

## Reporting

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue for a suspected vulnerability involving signature verification, credential parsing, trust decisions, or private-key exposure.

## Security model

- Ed25519 private keys remain issuer-only. They must not be committed, embedded in applications, or copied into CI logs.
- Applications embed only a public trust store.
- The signature authenticates the exact payload bytes.
- Core schemas fail closed; extensions are the only open namespace.
- Offline credentials cannot learn that a remote refund or revocation occurred. Products requiring timely control must refresh signed state or require short-lived activation leases.
- Local policy enforcement can be patched by an attacker controlling the client. Permit prevents credential forgery; it is not anti-tamper DRM.
- Clock-based expiration assumes a sufficiently trustworthy local clock. High-value managed products should combine short leases with server-observed refresh history.

## Key operations

- Use separate keys for production entitlements, staging, and application updates.
- Store production private keys in an OS secure store, HSM, or managed signing system when available.
- Pre-distribute a `next` public key before issuing with it.
- Mark a no-longer-used key `retired`; reserve `revoked` for compromise or explicit invalidation.
- A compromised private key requires a trust-store update through the application's authenticated update channel.

## Supported versions

Until a 1.0 release, only the latest `main` branch and latest tagged v0.x release receive security fixes.
