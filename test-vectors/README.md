# Cross-language test vectors

`v1/` is the portable conformance corpus for Permit Protocol v1. The positive entitlement is signed with RFC 8032 test key 1. Its private seed is public test material and MUST NOT be used outside tests.

A conforming implementation should at minimum:

1. Read `entitlement-payload.json` as binary bytes without newline conversion.
2. Confirm its byte length and SHA-256 from `vector.json`.
3. Verify `signature_base64` with the raw Ed25519 public key or SPKI key.
4. Verify `entitlement.permit.json` against `trust-store.json`.
5. Reject `tampered-payload.permit.json` at signature verification.
6. Reject `unknown-key.permit.json` before treating its payload as authorized.
7. Accept the historical credential with `retired-trust-store.json`.
8. Reject it with `revoked-trust-store.json`.
9. Reject it with `next-future-trust-store.json` because its authenticated `issued_at` predates that key's issuance window.
10. Reject `duplicate-key-alias-trust-store.json`.
11. Apply the policy cases listed in `conformance.json`.

JSON canonicalization is intentionally irrelevant. The exact decoded payload bytes are the signed message. Protocol v1 uses canonical padded standard Base64 for the envelope spelling.

`conformance.json` is descriptive rather than an RPC contract: implementations may structure their test harness however they prefer, but should produce the stated outcomes.
