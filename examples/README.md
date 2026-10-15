# Permit payload examples

These are unsigned, schema-valid Protocol v1 payload templates. Replace the sample identity, issuer, dates, grants, and limits, then sign the exact file bytes with `raco permit issue`.

- `perpetual.json` — permanent use, updates, and features.
- `maintenance.json` — permanent use with a Surge-Mac-style update cutoff.
- `feature-window.json` — permanent use with a Surge-iOS-style new-feature cutoff.
- `subscription.json` — true time-limited use.
- `team-managed.json` — team limits plus required activation lease.
- `trial.json` — finite signed trial.

One entitlement should represent one coherent commercial lifecycle. If a permanent local product and a hosted subscription have different expiry/management rules, issue separate entitlements rather than overloading one credential.
