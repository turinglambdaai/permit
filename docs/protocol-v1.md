# Permit Protocol v1

This document is normative for the wire format implemented by Permit v0.1. The words MUST, MUST NOT, SHOULD, and MAY have their usual RFC 2119 meanings.

## 1. Design goals

Permit is **offline-verifiable and online-manageable**:

- A client MUST be able to verify a credential without contacting an issuer.
- An issuer MAY refresh long-lived entitlements or issue short-lived activation leases.
- A purely offline entitlement cannot be instantly revoked. A product that needs timely revocation MUST use refreshed revocation data or short-lived activation leases.
- A server response is never trusted merely because it says `true`; management services issue signed credentials that remain locally verifiable.

Protocol v1 defines entitlement evidence, not checkout, payment, tax, accounts, email delivery, dashboards, or a hosted management API.

## 2. Exact-payload envelope

The envelope is a UTF-8 JSON object with exactly these fields:

| Field | Value |
| --- | --- |
| `permit_version` | integer `1` |
| `algorithm` | string `Ed25519` |
| `key_id` | non-empty string selecting a trust-store key |
| `payload` | standard padded Base64 of the exact payload bytes |
| `signature` | standard padded Base64 of a 64-byte Ed25519 signature |

Signing is:

```text
signature = Ed25519.Sign(private_key, BASE64_DECODE(payload))
```

Verification MUST decode `payload`, verify its signature, and only then parse it. It MUST NOT sign or verify a JSON re-serialization. Whitespace, property order, and a trailing newline are therefore authenticated data.

Unknown or missing envelope fields MUST be rejected.

## 3. Common credential rules

The payload is UTF-8 JSON containing exactly one object. Security-critical objects have closed schemas. Unknown core fields MUST be rejected. Vendor additions belong under `extensions`, whose keys SHOULD be namespaced, such as `example.com/order_id`.

All timestamps MUST use fixed-width UTC RFC 3339 form:

```text
YYYY-MM-DDTHH:MM:SSZ
```

Calendar dates, local times, and floating timestamps are not permitted.

Every credential has:

- `protocol`: `permit`
- `version`: `1`
- `type`: a supported credential type
- `credential_id`: globally unique, stable identifier
- `issuer`: stable issuer identifier, matched against the trust store
- `issued_at`: signing time
- `not_before`: activation time or `null`
- `extensions`: JSON object

Verifiers MUST reject a credential issued in the future or evaluated before `not_before`.

## 4. Entitlement and trial

`entitlement` and `trial` share the same shape and policy API. Their exact fields are:

```text
protocol, version, type, credential_id, issuer, issued_at, not_before,
subject, channel, grants, constraints, extensions
```

`subject` contains exactly:

```json
{"type":"person|organization|account|device|installation|anonymous",
 "id":"stable-id",
 "display":"optional human label or null"}
```

The implementation permits future subject type strings but treats `id`, not `display`, as identity.

`channel` separates commercial context from product edition. Typical values are `commercial`, `trial`, `education`, `nfr`, `internal`, `beta`, and `oem`.

### 4.1 Grants

`grants` is a non-empty list. Each grant has exactly:

```json
{
  "scope": {
    "products": ["gptp-studio"],
    "product_families": ["automotive-tools"]
  },
  "edition": "pro",
  "features": ["pcap-export"],
  "addons": ["report-pack"],
  "capabilities": {"packet-store-limit": 50000}
}
```

A scope MUST name at least one product or product family. Multiple products express a bundle. Features and add-ons are exact identifiers; applications SHOULD namespace globally shared identifiers. Capabilities are signed scalar strings, booleans, or numbers.

### 4.2 Constraints

`constraints` has exactly:

| Field | Meaning |
| --- | --- |
| `use_expires_at` | Last instant the granted product may run, or `null` |
| `updates_through` | Latest permitted release publication time, or `null` |
| `features_through` | Latest permitted feature publication time, or `null` |
| `version_policy` | Optional inclusive `min` and `max` SemVer-compatible bounds |
| `limits` | `named_seats`, `device_activations`, `concurrent_seats`; each integer or `null` |
| `installation_id` | Required installation identifier or `null` |
| `activation_required` | Whether a matching activation credential is mandatory |

The time windows are independent:

- `use_expires_at = null` is perpetual use.
- A release is update-entitled when `release.published_at <= updates_through`, or the cutoff is `null`.
- A feature is entitled when `feature.published_at <= features_through`, or the cutoff is `null`.

Products MUST attach immutable publication timestamps to releases and paid feature cohorts. Changing a timestamp after sale would change contractual policy.

## 5. Activation lease

An activation is not a replacement license. It is short-lived evidence that a management service currently allocates one installation against an entitlement.

The payload contains exactly:

```json
{
  "protocol": "permit",
  "version": 1,
  "type": "activation",
  "credential_id": "act_...",
  "entitlement_id": "ent_...",
  "issuer": "example.com",
  "issued_at": "2026-10-15T00:00:00Z",
  "not_before": null,
  "lease_id": "lease_...",
  "installation_id": "ins_...",
  "valid_until": "2026-10-22T00:00:00Z",
  "offline_grace_seconds": 604800,
  "extensions": {}
}
```

An activation is valid only when:

- its signature and schema are valid;
- its `entitlement_id` matches the entitlement credential;
- its `installation_id` matches the local stable installation ID;
- time is within `not_before` and `valid_until + offline_grace_seconds`.

`installation_id` SHOULD be random and stable for an application installation. It MUST NOT be a raw hardware serial, MAC address, advertising ID, or other invasive fingerprint. The management service decides how installations are allocated and released.

## 6. Trust store and rotation

A trust store has:

```json
{
  "protocol": "permit-trust-store",
  "version": 1,
  "issuer": "example.com",
  "keys": {
    "license-2026": {
      "algorithm": "Ed25519",
      "public_key": "<Base64 SubjectPublicKeyInfo DER>",
      "status": "active",
      "not_before": null,
      "not_after": null
    }
  }
}
```

Statuses are `next`, `active`, `retired`, and `revoked`.

- `next`, `active`, and `retired` keys may verify inside their time window.
- `retired` means “do not issue new credentials”, not “invalidate old credentials”. Issuers enforce signing policy.
- `revoked` keys MUST fail verification.
- Clients SHOULD ship current, previous, and next public keys before rotating issuance.

Replacing an embedded trust store requires the application's normal authenticated update path. Permit signing keys SHOULD be separate from application-update signing keys.

## 7. Fail-closed behavior

Verifiers MUST reject:

- unsupported protocol versions or algorithms;
- unknown/missing fields outside `extensions`;
- unknown credential types;
- invalid Base64, key IDs, signatures, issuers, timestamps, or field types;
- revoked or out-of-window trust keys;
- activation/installation mismatches.

Applications MUST authorize from a successfully verified credential object, never from raw inspected JSON.

## 8. Reserved evolution

Future protocol versions may add revocation lists, delegation, migration, trial-extension commands, store receipts, or enterprise floating leases. Protocol v1 does not assign wire semantics to those types. A v1 verifier rejects them rather than guessing.
