# Permit adoption and support

**English** · [简体中文](USING.zh-CN.md)

## When to use it

Compose Permit beside an application when signed, offline-verifiable rights are needed. Start with an entitlement and omit activation unless the product explicitly needs an online lease. Free products do not need a licensing subsystem.

## Requirements and maturity

The Racket implementation requires the runtime and crypto dependencies declared by the package. Protocol v1 is implemented, but a stable 1.0 compatibility promise has not been declared. Independent verifiers must execute the normative vectors.

## One useful verification

Keep issuer private keys server-side and public trust stores in clients. Verify first, then evaluate product/time/feature policy. Revisions replace snapshots the client has received; they do not revoke an offline credential immediately. Preserve backup/rotation paths for perpetual rights and separate entitlement keys from update/publisher keys.

## Reading path

1. [First signed right](getting-started.md)
2. [Protocol v1](protocol-v1.md)
3. [Trust model](trust-model.md)
4. [Framework boundary](framework-integration.md)
5. [Compatibility](compatibility.md)

Technical references retain one normative meaning. Chinese onboarding explains and links to that reference rather than creating a second protocol.

## Upgrades, data and support

Record the package versions and platforms your application actually tests. Read CHANGELOG and compatibility contracts before upgrading, test user-data migration on copies and retain a recoverable version. A library does not supply your product’s database backup, publisher identity, refunds, account recovery or privacy policy. Example customer/offer identifiers and amounts are fixtures, not live offers.

Use [Issues](https://github.com/turinglambdaai/permit/issues) in English or Chinese. Include package/commit, Racket version, OS/architecture, a minimal reproduction and the first redacted error. Never attach real keys, customer credentials, raw payment data or private documents. Community support has no guaranteed response time.

[Private vulnerability reporting](../SECURITY.md).

[Current licence](../LICENSE) · [CHANGELOG](../CHANGELOG.md)
