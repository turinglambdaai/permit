# Entitlements and trials — Protocol v1

This document is normative for Permit v1 `entitlement`, `trial`, and `trial-extension` payloads.

## Entitlement-like payload

`entitlement` and `trial` contain exactly:

```text
protocol, version, type, credential_id, entitlement_id, revision,
issuer, issued_at, not_before, subject, channel, grants, constraints,
extensions
```

### Identity

- `credential_id` identifies one signed statement.
- `entitlement_id` identifies the logical commercial right across renewals/reissues.
- `revision` is a non-negative integer. A reissue of the same logical right increments it.
- `issuer` is matched to the trust store.
- `issued_at` is the authenticated signing/issuance time.
- `not_before` is `null` or the earliest policy activation time.

### Subject

`subject` contains exactly:

```json
{
  "type": "person",
  "id": "cus_01...",
  "display": "customer@example.com"
}
```

`id` is the stable identity. `display` is optional human-facing metadata and may be `null`. Typical subject types include `person`, `organization`, `account`, `device`, `installation`, and `anonymous`. Products must not use `display` as an identity key.

### Channel

`channel` describes the commercial context independently of edition. Common values include `commercial`, `trial`, `education`, `nfr`, `internal`, `beta`, and `oem`.

## Grants

`grants` is a non-empty list. Each grant contains exactly:

```json
{
  "scope": {
    "products": ["gptp-studio"],
    "product_families": ["automotive-tools"]
  },
  "edition": "pro",
  "features": ["pcap-export"],
  "addons": ["report-pack"],
  "capabilities": {
    "packet-store-limit": 50000
  }
}
```

A scope MUST name at least one product or product family. Identifier lists MUST NOT contain duplicates.

`edition` is either a non-empty string or `null`; `null` lets a credential grant only an add-on/feature without pretending to change the product edition. Features and add-ons are boolean rights. Capabilities are finite signed scalar values. If several matching grants define the same capability with different values, a conforming policy engine must fail closed rather than silently depend on list order.

## Constraints

`constraints` contains exactly:

| Field | Meaning |
| --- | --- |
| `use_expires_at` | final instant the right may be used, or `null` for perpetual |
| `updates_through` | final release publication instant entitled, or `null` |
| `features_through` | final new-feature publication instant entitled, or `null` |
| `version_policy` | inclusive SemVer 2.0 `min` / `max`, each string or `null` |
| `limits` | named seats, device activations, concurrent seats |
| `installation_id` | optional application-generated binding |
| `activation_required` | whether a matching activation lease is mandatory |

The three time windows are independent.

### Common commercial shapes

**Perpetual purchase**

```text
use_expires_at  = null
updates_through = null
features_through = null
```

**Perpetual + maintenance updates**

```text
use_expires_at  = null
updates_through = maintenance_end
```

An installed version published before the cutoff remains usable after the cutoff.

**Perpetual + future-feature window**

```text
use_expires_at   = null
features_through = feature_window_end
```

Features published before the cutoff remain owned after the cutoff.

**True subscription**

```text
use_expires_at = subscription_end
```

After that instant the policy is unusable unless a newer revision extends it.

## Trials

A `trial` uses the same grants and constraints, but `use_expires_at` MUST be finite. This makes product code query rights the same way during a trial and after purchase.

A product may also maintain a purely local first-run trial outside the signed wire protocol. Such local state is convenience state, not forgery-resistant evidence, and can be deleted or rolled back by a user controlling the machine.

## Trial extension

A signed `trial-extension` contains exactly:

```json
{
  "protocol": "permit",
  "version": 1,
  "type": "trial-extension",
  "credential_id": "ext_...",
  "trial_id": "trial_support_01",
  "issuer": "example.com",
  "issued_at": "2026-10-15T00:00:00Z",
  "not_before": null,
  "use_expires_at": "2026-10-29T23:59:59Z",
  "extensions": {}
}
```

For a signed Permit trial, `trial_id` matches that trial's `entitlement_id`.

The extension carries an **absolute** `use_expires_at`, not “add N days”. Applying the same extension twice therefore cannot accumulate time. When several applicable extensions are present, the effective expiry is the latest of the base trial expiry and the valid extension expiries.

## Revision lifecycle

Renewal or plan change issues a new credential:

```text
entitlement_id = ent_customer_01   (stable)
credential_id  = cred_2027_renewal (new)
revision       = 3                 (increased)
```

Applications may select the highest revision they have received. They must not claim that this revokes hidden or never-refreshed offline revisions. Timely downgrade or revocation requires a management mechanism such as activation leases or signed revocation state.


## Scope of standard limits

The standard `named_seats`, `device_activations`, and `concurrent_seats` limits apply to the logical entitlement as a whole. This is deliberate: a bundle sold under one commercial right normally shares its seat pool.

If two products need independently administered seat pools or different lifecycle windows, issue separate entitlements. Do not overload one credential with ambiguous per-product allocation semantics.
