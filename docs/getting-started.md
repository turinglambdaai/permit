# Getting started

This guide takes one unsigned entitlement from a template to a verified product decision. No account, payment provider, or server is required.

[中文版](getting-started.zh-CN.md)

## The two sides

Permit deliberately separates issuance from product verification:

```text
issuer workspace                     shipped product
----------------                     ---------------
private-key.der       never ships
trust-store.json  -----------------> public trust store
entitlement.json      sign once
entitlement.permit.json -----------> customer credential
```

The private key belongs only in the issuer environment. The application receives public trust data and signed credentials.

## 1. Install Permit

```bash
raco pkg install --auto --name permit https://github.com/turinglambdaai/permit.git
raco permit help
```

## 2. Create an entitlement-only key

Run this in a private issuer workspace:

```bash
raco permit keygen --private private-key.der --public public-key.der --trust-store trust-store.json --key-id entitlement-2026 --issuer com.example --purpose entitlement
```

The command creates:

| File | Purpose | Ship with the product? |
| --- | --- | --- |
| `private-key.der` | Signs entitlements | **No** |
| `public-key.der` | Standalone public key copy | Optional |
| `trust-store.json` | Public keys and their allowed uses | **Yes** |

Commit neither a real private key nor a real customer credential to source control.

## 3. Prepare the payload

Copy [`examples/perpetual.json`](../examples/perpetual.json) to `entitlement.json`. At minimum, review these fields:

- `credential_id`: unique id for this signed statement;
- `entitlement_id`: stable id for the commercial right across renewals;
- `issuer`: exactly `com.example`, matching the trust store;
- `issued_at`: the real UTC issuance time;
- `subject`: the customer, organization, installation, or anonymous holder;
- `grants`: the products, editions, features, add-ons, and capabilities;
- `constraints`: expiry, update/feature windows, versions, limits, and activation policy.

The payload is ordinary UTF-8 JSON, but its exact bytes are signed. Finish editing before issuance. Reformatting it afterward produces a different message and invalidates the signature.

## 4. Issue the credential

Use `issue`, the policy-checked issuer path:

```bash
raco permit issue --key private-key.der --key-id entitlement-2026 --trust-store trust-store.json --payload entitlement.json --output entitlement.permit.json
```

`issue` rejects a mismatched issuer, wrong private key, inactive key, disallowed credential type, invalid issuance time, or invalid payload schema. Use the lower-level `sign` command only for recovery or conformance tooling where those checks are intentionally handled elsewhere.

## 5. Verify before trusting claims

```bash
raco permit verify --trust-store trust-store.json --credential entitlement.permit.json
```

A successful result means that the signature, key, issuer, issuance window, key purpose, and payload schema are valid. It does not by itself answer whether a particular feature is allowed.

`raco permit inspect` is only a diagnostic decoder. Its output is explicitly unverified and must never authorize product behavior.

## 6. Ask a product question

The template grants the `pro` edition of `example-app`:

```bash
raco permit check --trust-store trust-store.json --credential entitlement.permit.json --product example-app --edition pro
```

The JSON result includes the overall usability decision, rejection reasons, and the requested policy result. Supply evaluation context such as `--version`, `--installation-id`, `--activation`, or publication timestamps whenever the signed policy requires it. Missing required context fails closed.

## 7. Embed verification in a Racket application

```racket
#lang racket/base

(require permit)

(define trust-store (read-trust-store "trust-store.json"))
(define credential
  (verify-credential "entitlement.permit.json" trust-store))

(unless (edition-entitled? credential "example-app" "pro")
  (error 'startup "this installation is not entitled to the pro edition"))
```

`verify-credential` either returns a sealed `verified-credential` or raises an error. Product policy functions accept that verified value, so untrusted JSON cannot accidentally enter the authorization path.

## Choose the next model only when needed

- Start with [`examples/perpetual.json`](../examples/perpetual.json) for a simple perpetual purchase.
- Add an update cutoff with [`examples/maintenance.json`](../examples/maintenance.json).
- Add a new-feature window with [`examples/feature-window.json`](../examples/feature-window.json).
- Use [`examples/subscription.json`](../examples/subscription.json) for finite use rights.
- Read [activation leases](activation-v1.md) before setting `activation_required`.
- Read [local trials](local-trials.md) before choosing signed trials or client-only first-run state.
- Read the [trust model](trust-model.md) before rotating or revoking keys.

## Production checklist

- Keep private signing keys outside application bundles and source control.
- Give online activation signers only the `activation` purpose; do not let them mint perpetual entitlements.
- Keep Permit credential keys separate from update signing and OS publisher keys.
- Verify first, then evaluate policy; never authorize from decoded-but-unverified claims.
- Preserve retired public keys needed by valid perpetual credentials.
- Treat `installation_id` as a random application identifier, not a hardware fingerprint.
- Test your integration against [`test-vectors/v1/`](../test-vectors/v1/) before shipping.
