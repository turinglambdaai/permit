# Cross-language test vectors

The [`v1/`](v1/) directory is the portable conformance corpus for Permit Protocol v1. It lets another implementation prove that it authenticates the same bytes and reaches the same policy decisions as the Racket reference implementation.

You do not need these files to use Permit from Racket. Use them when implementing Permit in another language, auditing a verifier, or checking that an application integration has not changed protocol semantics.

## Start here

1. Read [`v1/credential-vectors.json`](v1/credential-vectors.json). It lists every positive payload and credential pair, including byte length, SHA-256, and Ed25519 signature.
2. Read each `*-payload.json` as **binary bytes**. Do not parse and re-serialize it before signature verification.
3. Decode the envelope's padded standard Base64 `payload` and confirm it equals the payload file byte for byte.
4. Verify the signature and trust policy with [`v1/trust-store.json`](v1/trust-store.json).
5. Apply the positive and negative cases in [`v1/conformance.json`](v1/conformance.json).

## Positive credentials

| Model | Payload | Signed credential | What it exercises |
| --- | --- | --- | --- |
| Perpetual entitlement | `entitlement-payload.json` | `entitlement.permit.json` | grants, limits, version and maintenance windows |
| Managed entitlement | `managed-entitlement-payload.json` | `managed-entitlement.permit.json` | activation requirement and published-through features |
| Activation lease | `activation-payload.json` | `activation.permit.json` | exact entitlement snapshot, installation binding, offline grace |
| Signed trial | `trial-payload.json` | `trial.permit.json` | finite use window |
| Trial extension | `trial-extension-payload.json` | `trial-extension.permit.json` | absolute extension and replay-safe idempotence |

All positive credentials use RFC 8032 test key 1. Its private seed is public test material and **must never be used for real credentials**. [`v1/generate.rkt`](v1/generate.rkt) reproduces the four additional signed envelopes from the checked-in payload bytes; the original entitlement vector remains fixed for compatibility.

## Required rejection cases

A conforming implementation must also:

- reject `tampered-payload.permit.json` during signature verification;
- reject `unknown-key.permit.json` before treating its payload as authorized;
- accept the historical entitlement with `retired-trust-store.json`;
- reject it with `revoked-trust-store.json`;
- reject it with `next-future-trust-store.json` because its authenticated `issued_at` predates the key's issuance window;
- reject `duplicate-key-alias-trust-store.json`;
- reject an entitlement under `activation-only-trust-store.json`;
- reject `duplicate-member-envelope.json` before authorization.

The policy corpus additionally fixes inclusive cutoff behavior, missing-context fail-closed behavior, activation installation binding, exact offline-grace boundaries, signed-trial expiry, and idempotent trial extensions.

## What is normative

The signed message is the exact decoded payload byte sequence. JSON canonicalization is intentionally irrelevant. Protocol v1 requires canonical padded standard Base64 for envelope fields, but whitespace inside the payload is authenticated like every other byte.

`conformance.json` is descriptive rather than an RPC contract. Implementations may structure their harness however they prefer, but must produce the stated outcomes. Existing vectors are append-only compatibility fixtures: do not silently regenerate or reinterpret them after release.
