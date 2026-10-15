# Local trials and installation identity

Permit Protocol v1 describes signed product rights. A first-run or user-started local trial is different: before an application contacts an issuer, there is nobody who can sign a unique per-installation trial credential.

Permit therefore provides a small **non-protocol** local trial runtime.

## Installation identity

```racket
(define installation-id (generate-installation-id))
```

The value is a random 128-bit identifier such as `ins_...`. Persist it with the application state that owns it. It is not derived from a motherboard, MAC address, OS machine id, advertising id, username, or hostname.

An installation id is an allocation identifier, not a secret.

## Start a local trial

```racket
(define trial
  (make-local-trial #:duration-seconds (* 14 24 60 60)))
```

The state records:

- a random `trial_id`;
- immutable `started_at`;
- immutable base `expires_at`;
- a `last_seen_at` high-water mark.

The host chooses storage. A Rivet application can use its normal application/secure-storage primitives; another framework can use its own storage. Permit does not depend on either framework.

Persist the state returned by every evaluation:

```racket
(define evaluation (evaluate-local-trial trial))
(save-state! (local-trial-evaluation-state evaluation))

(when (local-trial-evaluation-active? evaluation)
  (enable-pro-preview!))
```

The high-water mark detects obvious wall-clock rollback. Small clock adjustments are tolerated by default. This is nuisance resistance, not DRM.

## Signed support extension

Support can issue a normal Protocol v1 `trial-extension` whose `trial_id` matches the local trial id. After verifying that credential with the product trust store:

```racket
(evaluate-local-trial
 trial
 #:issuer "com.example"
 #:extensions (list verified-extension))
```

The extension contains an absolute `use_expires_at`. Re-importing the same extension cannot accumulate extra days.

## Threat boundary

A user controlling the machine can delete or restore local state, patch the application, or roll the clock together with stored state. Permit intentionally does not claim to make a fully offline local trial unresettable.

For higher-value products that require stronger control, use signed entitlements plus short-lived activation leases. For ordinary independent desktop software, the local trial helper is intended to reduce accidental resets and support complexity without punishing legitimate users.
