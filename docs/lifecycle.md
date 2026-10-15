# Credential lifecycle

This document describes the intended operational lifecycle around Protocol v1.

## 1. First purchase

The issuer creates a logical entitlement id and revision 0:

```text
entitlement_id = ent_01
revision       = 0
credential_id  = cred_01
```

The product verifies the signed credential locally and evaluates its grants and constraints.

## 2. Maintenance or subscription renewal

Renewal does not mutate an old signed file. The issuer creates a new statement:

```text
entitlement_id = ent_01   # same lineage
revision       = 1        # increment
credential_id  = cred_02  # new signed statement
updates_through / use_expires_at = renewed values
```

When both statements are available, the client chooses the highest revision.

This does not remotely invalidate revision 0. If the customer preserves only revision 0 on an offline machine, that machine continues to know exactly what revision 0 promised.

## 3. Plan changes

Upgrade, downgrade, seat-count change, or bundle change uses the same revision mechanism. The replacement statement carries the complete new rights snapshot rather than a patch.

Complete snapshots are easier to audit, cache, restore, and verify than an unbounded chain of signed mutations.

## 4. Managed activation

If `activation_required = true`, the product also needs an activation bound to the exact entitlement id, revision, credential id, and installation id.

A renewal normally produces:

```text
new entitlement revision
        +
new activation lease for that revision
```

This prevents a fresh lease from silently extending stale rights.

## 5. Trial support

Signed trials are finite entitlement-like credentials. Customer support may issue a `trial-extension` containing an absolute later expiry. Re-importing the same extension has no cumulative effect.

A lightweight product may instead implement a local first-run trial using its own storage. Permit does not pretend that local client state is tamper-proof.

## 6. Offline replacement

For early independent-developer sales, the complete workflow may remain:

```text
customer pays
  -> developer issues new signed credential
  -> sends file
  -> customer imports it
```

No account or license server is required.

## 7. Future online management

A future service may automate:

- payment webhook to revision issuance;
- activation allocation and refresh;
- device release/transfer;
- organization seat administration;
- signed revocation distribution;
- air-gapped request/response workflows.

The management service outputs signed Permit artifacts. It does not become an online boolean oracle for products that promise offline use.
