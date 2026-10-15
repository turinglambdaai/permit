# Activation leases — Protocol v1

Activation is an optional management layer. It is not a replacement for the durable entitlement.

A product that promises fully offline perpetual use normally does not require activation. A product that needs device allocation, concurrent-seat management, subscription refresh, or timely revocation can require a short-lived activation lease.

## Payload

An `activation` contains exactly:

```json
{
  "protocol": "permit",
  "version": 1,
  "type": "activation",
  "credential_id": "act_...",
  "entitlement_id": "ent_customer_01",
  "entitlement_revision": 3,
  "entitlement_credential_id": "cred_2027_renewal",
  "issuer": "example.com",
  "issued_at": "2027-01-01T00:00:00Z",
  "not_before": null,
  "lease_id": "lease_...",
  "installation_id": "ins_random_...",
  "valid_until": "2027-01-08T00:00:00Z",
  "offline_grace_seconds": 604800,
  "extensions": {}
}
```

## Exact snapshot binding

An activation is usable only when all three entitlement references match the entitlement being evaluated:

- `entitlement_id`
- `entitlement_revision`
- `entitlement_credential_id`

This prevents a newly refreshed activation from accidentally authorizing an older or different rights snapshot.

The `installation_id` must also match the local installation.

## Installation identity

`installation_id` SHOULD be random, opaque, application-generated, and stable for that installation.

It MUST NOT be a raw hardware serial, MAC address, advertising identifier, or other invasive fingerprint. A product may preserve the random id across normal upgrades. Reinstall/migration policy belongs to the management plane.

## Time and grace

The activation is effective only after authenticated `issued_at` and `not_before`, and through:

```text
valid_until + offline_grace_seconds
```

Grace is an explicit product promise, not an implicit network-error rule. Products needing strict online control can set it to zero; offline-tolerant subscriptions can choose a bounded value.

Clock rollback remains a client-side threat. High-value managed products should combine short leases with server-observed refresh history.

## Seats and devices

The entitlement may state `named_seats`, `device_activations`, and `concurrent_seats` as separate signed limits. Permit v1 does not define a central allocator. A future management service decides who occupies a seat and issues leases as evidence of that decision.

A purely offline client cannot reliably enforce a global floating-seat count across multiple machines.
