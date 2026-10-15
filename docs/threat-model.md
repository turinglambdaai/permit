# Threat model

Permit is a credential authenticity and product-rights protocol. It is not anti-tamper DRM.

## Adversary assumptions

A local attacker may:

- copy or edit credential files;
- inspect and patch the application binary;
- delete or roll back local state;
- manipulate the local clock;
- block network access;
- replay previously received offline credentials.

A network attacker may modify transport traffic unless another authenticated layer protects it. Permit therefore treats signed credentials, not HTTP responses, as authorization evidence.

## What Permit protects

With an uncompromised issuer private key, Permit is designed to prevent:

- forging product rights;
- editing signed grants, limits, dates, or installation bindings;
- substituting a credential from another issuer/trust store;
- using an activation lease with a different entitlement id, revision, credential id, or installation id;
- silently interpreting misspelled/unknown core security fields;
- making permanent licenses fail merely because an old signing key was retired.

## What Permit does not protect

### Patched clients

A user controlling the executable can remove policy checks. Permit raises the cost of credential forgery; it cannot make client code unpatchable.

### Offline revocation

A permanently offline entitlement cannot learn that a refund, downgrade, or revocation occurred elsewhere. Revision numbers do not solve this because the user can hide the newer statement.

Products requiring timely control must use refreshed signed state, short-lived activation leases, or another explicitly online policy.

### Clock rollback

Expiry and offline grace use the client's notion of time. Applications may store a monotonic "last seen" timestamp in secure storage as nuisance resistance, but a fully controlled client can still patch or roll back that state.

### Local trial reset

Purely local first-run trials can be reset by deleting or restoring local state. Do not spend disproportionate engineering effort pretending otherwise.

### Private-key compromise

Possession of a Permit private key allows forging credentials accepted by clients that trust its public key. Rotate and distribute updated trust state, mark the compromised key `revoked`, and use a separate key for future issuance.

## Operational guidance

- keep production private keys out of application builds and source repositories;
- separate Permit, update-feed, code-signing, staging, and test keys;
- pre-distribute future public keys before rotation;
- use short activation leases only when the product actually needs online management;
- default consumer/local tools to no hardware fingerprinting and no mandatory phone-home;
- use random installation ids when device allocation is needed.
