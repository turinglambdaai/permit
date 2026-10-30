# Native Ed25519 providers and official package-build evidence

Permit Protocol v1 requires **Ed25519**, not a choice of signature algorithm.
The Racket reference implementation uses the audited `crypto-lib` factories
in a fixed order: **OpenSSL 3+** (`crypto/libcrypto`), then
**libsodium** (`crypto/sodium`). Both produce and verify the same RFC 8032
Ed25519 signatures and canonical key formats. The public credential envelope
and signing semantics do not change when a backend changes. There is no weak
or non-cryptographic fallback.

The native system libraries are optional at Racket package compilation time;
they are required at **credential key generation, parsing, signing and
verification** runtime. OpenSSL 3+ is usually bundled with a full Racket
distribution. libsodium requires a compatible `libsodium` shared library
(e.g., the version supported by `crypto-lib` on the target platform).
Operators must provide a vetted native provider. If neither is available,
Permit raises an error; it must not silently accept a credential or skip
signature checks.

## Diagnosing an unsupported native environment

Run in the exact Racket environment used to verify or issue credentials:

```sh
racket -e '(require crypto crypto/libcrypto crypto/sodium) (displayln (list (factory-version libcrypto-factory) (factory-version sodium-factory)))'
raco test -p permit
```

A `#f` factory version indicates the native implementation was unavailable.
Always verify the RFC 8032 known-answer test, invalid signature rejection,
trust-store key parsing, issuer key generation, and cross-language C vectors;
`raco make` alone cannot prove Ed25519 works.

## Official Racket package build service

The 2026-10-29 [official `permit` package build transcript](https://pkg-build.racket-lang.org/server/built/test-fail/permit.txt)
compiled successfully but failed 6 tests due to an unavailable Ed25519
provider/key parsing path, despite the upstream GitHub matrix succeeding.
This is a concrete environment portability issue, **not** permission to
remove or skip cryptographic assertions. The candidate backend fallback
is only a proposed mitigation until a new official catalog build on that
commit reports success.

Before calling a release or this issue resolved:

1. Run the cross-platform GitHub Racket/C test matrix on the exact new
   commit and record checks which have actually completed.
2. After merge/publish, inspect the public
   [Permit package build result](https://pkgs.racket-lang.org/package/permit)
   and the exact build-failure transcript, if any. If the official machine
   has neither required native provider, record an explicit unsupported
   environment rather than manufacturing a green test outcome.
3. Install `permit` **by published package name** from a clean Racket
   environment and run its tests and sample verifier.
4. Revalidate Commerce's pinned Permit integration; the released dependency
   must not be assumed compatible from unit tests alone.

This is operational backend selection, not key custody, a protocol change,
a relaxation of Ed25519 verification, or permission to place private keys
in customer applications.
