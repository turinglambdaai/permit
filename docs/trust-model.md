# Trust model — Protocol v1

Permit applications ship public trust. Issuers keep private signing keys outside application bundles.

## Trust store

A v1 trust store is:

```json
{
  "protocol": "permit-trust-store",
  "version": 1,
  "issuer": "example.com",
  "keys": {
    "license-2027": {
      "algorithm": "Ed25519",
      "public_key": "<Base64 SubjectPublicKeyInfo DER>",
      "status": "active",
      "not_before": "2027-01-01T00:00:00Z",
      "not_after": null
    }
  }
}
```

The trust store is application configuration delivered through the application's authenticated release/update path.

## Key status

- `next` — pre-distributed key intended for future issuance;
- `active` — normal issuance key;
- `retired` — no new issuance intended, but old credentials remain authentic;
- `revoked` — compromise or explicit distrust; all credentials under this key fail verification.

## Issuance window

`not_before` and `not_after` constrain the authenticated credential `issued_at`.

They do **not** mean “clients may only verify this public key until this wall-clock date”.

Example:

```text
key not_after      = 2027-12-31
credential issued  = 2027-06-01
client verifies    = 2035-04-01
result             = authentic
```

This is required for perpetual offline entitlements.

A credential claiming `issued_at = 2028-01-01` under that key is rejected even when the Ed25519 signature is mathematically valid.

## Rotation

Recommended rotation:

1. Ship a trust store containing the future public key as `next`, preferably with its future issuance `not_before`.
2. Release that application update widely.
3. Start issuing with the new key and mark it `active`.
4. Mark the old key `retired`; keep it so historical perpetual credentials continue to verify.
5. Use `revoked` only when old credentials must no longer be trusted because the signing key was compromised or explicitly invalidated.

Revocation of an embedded public key requires the application to receive updated trust state. A machine that remains permanently offline cannot learn new revocation information.

## Key separation

Permit credential-signing keys SHOULD be distinct from:

- application update-feed signing keys;
- platform code-signing certificates;
- TLS keys;
- staging/test credential keys.

Compromise of one trust domain should not automatically compromise another.

Production private keys belong in a secure operator environment such as an OS secure store, HSM, managed signing service, or a dedicated key-custody tool. They do not belong in source control.
