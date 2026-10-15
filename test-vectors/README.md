# Cross-language test vectors

`v1/` contains a deterministic Protocol v1 credential signed with RFC 8032 test key 1. The private seed is public test material and MUST NOT be used outside tests.

A conforming implementation should:

1. Read `entitlement-payload.json` as binary bytes without newline conversion.
2. Confirm its byte length and SHA-256 from `vector.json`.
3. Verify `signature_base64` with the raw Ed25519 public key or SPKI key.
4. Verify `entitlement.permit.json` against `trust-store.json`.
5. Reject the credential after changing any payload byte.
6. Parse and validate claims only after signature verification.

JSON canonicalization is intentionally irrelevant. The exact file bytes are the signed message.
