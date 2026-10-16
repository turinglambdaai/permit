#lang scribble/manual

@title[#:tag "permit"]{Permit: Signed Product Rights}
@author[(author+email "Turing Lambda" "jirentianxiang1024@gmail.com")]

@defmodule[permit]

Permit is a framework-neutral protocol and Racket reference
implementation for answering one product question: what may this
person, organization, or installation use right now? Long-lived
@emph{entitlements} describe commercial rights, optional short-lived
@emph{activation leases} bind a right to an installation, and local
first-run @emph{trials} are their own convenience state. Everything is
verified offline against an Ed25519 trust store that ships inside the
application; issuance and rotation are online concerns that never
change the verification protocol.

Permit is deliberately not anti-tamper DRM, and a permanently offline
credential cannot learn about a revocation that happened elsewhere —
see @hyperlink["https://github.com/turinglambdaai/permit/blob/main/docs/threat-model.md"]{the
threat model} for the honest boundaries. The normative protocol lives in
@hyperlink["https://github.com/turinglambdaai/permit/blob/main/docs/protocol-v1.md"]{Protocol
v1}; this manual documents the Racket surface.

@section{Trust stores}

Applications ship public keys only. A trust store is JSON application
configuration, delivered through the application's authenticated
release path:

@codeblock|{
{
  "protocol": "permit-trust-store",
  "version": 1,
  "issuer": "com.example",
  "keys": {
    "license-2027": {
      "algorithm": "Ed25519",
      "public_key": "<Base64 SubjectPublicKeyInfo DER>",
      "status": "active",
      "purposes": ["entitlement", "trial", "trial-extension"],
      "not_before": "2027-01-01T00:00:00Z",
      "not_after": null
    }
  }
}
}|

Key statuses are @tt{next} (pre-distributed, must have @tt{not_before}),
@tt{active} (normal issuance), @tt{retired} (no new issuance, must have
an @tt{not_after} issuance cutoff — old credentials stay authentic), and
@tt{revoked} (every credential under the key fails). Each key declares
the credential types it may sign; an activation-signing key therefore
cannot mint a perpetual entitlement. The time windows constrain the
credential's authenticated @tt{issued_at}, not the wall clock at
verification — retiring a key never kills a perpetual entitlement.

@defproc[(read-trust-store [source (or/c path-string? input-port?)])
         trust-store?]{
Parses and validates a trust store document. Unknown key statuses,
missing purposes, and wrong algorithms are rejected here.
}

@defproc[(jsexpr->trust-store [value jsexpr?]) trust-store?]{
The same validation for an already-parsed document.
}

@defproc[(trust-store? [v any/c]) boolean?]{}
@defproc[(trust-store-issuer [store trust-store?]) string?]{
The only credential issuer this store will accept.
}

@section{Verifying credentials}

A credential is a small JSON envelope whose @tt{payload} is base64
bytes signed exactly with Ed25519. Verification authenticates those
bytes first and only then parses authorization claims — the verifier
never re-serializes JSON, which removes canonicalization ambiguity
across languages.

@defproc[(verify-credential [source (or/c path-string? input-port?)]
                            [store trust-store?])
         verified-credential?]{
Verifies signature, trust key, issuer, key purpose, and key issuance
window, then parses and schema-checks the payload. Any failure raises
@racket[exn:fail] — an invalid credential is an error, not a boolean.
}

@defproc[(verified-credential? [v any/c]) boolean?]{
Only values returned by @racket[verify-credential] satisfy this
predicate; the constructor is sealed so unverified claims cannot flow
into policy checks.
}

The claims accessors (all @racket[(-> verified-credential? ...)]):
@defproc[(verified-credential-type [c verified-credential?]) string?]{
@tt{"entitlement"}, @tt{"trial"}, @tt{"trial-extension"}, or
@tt{"activation"}.
}
@defproc[(verified-credential-id [c verified-credential?]) string?]{}
@defproc[(verified-credential-issuer [c verified-credential?]) string?]{}
@defproc[(verified-credential-issued-at [c verified-credential?]) string?]{}
@defproc[(verified-credential-entitlement-id [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-revision [c verified-credential?]) exact-nonnegative-integer?]{}
@defproc[(verified-credential-subject-type [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-subject-id [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-subject-display [c verified-credential?]) (or/c string? #f)]{
The customer-facing name (an email address, for example). Display only —
never an authorization input.
}
@defproc[(verified-credential-channel [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-use-expires-at [c verified-credential?]) (or/c string? #f)]{
Canonical UTC timestamp; @racket[#f] means the right does not expire.
}
@defproc[(verified-credential-updates-through [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-features-through [c verified-credential?]) (or/c string? #f)]{}

@section{Evaluating policy}

Policy evaluation is total and offline: every check takes the verified
credential, an evaluation instant (@racket[(current-rfc3339)] by
default), and optional binding parameters.

@defproc[(credential-usable? [c verified-credential?]
                             [#:at at string? (current-rfc3339)]
                             [#:installation-id installation-id (or/c string? #f) #f]
                             [#:activation activation (or/c verified-credential? #f) #f]
                             [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         boolean?]{
True when the credential is currently within its use window, matches
the installation binding if any, and carries a valid activation lease
if the entitlement demands one.
}

@defproc[(credential-status [c verified-credential?]
                            [#:at at string? (current-rfc3339)]
                            [#:installation-id installation-id (or/c string? #f) #f]
                            [#:activation activation (or/c verified-credential? #f) #f]
                            [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         (hash/c symbol? any/c)]{
The full verdict: @racket['usable?], @racket['reasons] (a list of
symbols such as @racket['use-expired] or @racket['not-active-yet]), and
@racket['effective_use_expires_at] after trial extensions.
}

@defproc[(activation-valid? [entitlement verified-credential?]
                            [activation verified-credential?]
                            [installation-id string?]
                            [#:at at string? (current-rfc3339)])
         boolean?]{
Checks that a lease is current and bound to the exact entitlement id,
revision, credential id, issuer, and installation.
}

@defproc[(trial-extension-valid? [trial verified-credential?]
                                 [extension verified-credential?]
                                 [#:at at string? (current-rfc3339)])
         boolean?]{
Checks the signed relationship and activation time of a trial extension.
}

@defproc[(edition-entitled? [c verified-credential?]
                            [product string?]
                            [edition string?]
                            [#:at at string? (current-rfc3339)]
                            [#:product-family product-family (or/c string? #f) #f]
                            [#:version version (or/c string? #f) #f]
                            [#:installation-id installation-id (or/c string? #f) #f]
                            [#:activation activation (or/c verified-credential? #f) #f]
                            [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         boolean?]{
True when a grant covers the product at the edition and the credential
is usable. The same keyword shape applies to
@racket[feature-entitled?], @racket[addon-entitled?], and
@racket[update-entitled?].
}

@defproc[(feature-entitled? [c verified-credential?]
                            [product string?]
                            [feature string?]
                            [#:published-at published-at (or/c string? #f) #f]
                            [#:at at string? (current-rfc3339)] ...
                            ) boolean?]{
Product-feature check with the @tt{published-through} window: a
feature published after @racket[features_through] is not covered, so a
perpetual customer keeps everything published inside the window they
bought. Requires @racket[#:published-at] — the application's honest
build-time or manifest timestamp for that feature.
}

@defproc[(update-entitled? [c verified-credential?]
                           [product string?]
                           [update-published-at string?]
                           [#:at at string? (current-rfc3339)] ...
                           ) boolean?]{
Update-rights check against @tt{updates_through}.
}

@defproc[(capability-value [c verified-credential?]
                           [product string?]
                           [capability symbol?]
                           [#:default default any/c #f]
                           [#:at at string? (current-rfc3339)] ...) any/c]{}
@defproc[(limit-value [c verified-credential?]
                      [limit symbol?]
                      [#:default default any/c #f]
                      [#:at at string? (current-rfc3339)] ...) any/c]{
Scalar capabilities and seat limits (named seats, device activations,
concurrent seats) from the credential's constraints.
}

@defproc[(version-allowed? [c verified-credential?] [version string?]) boolean?]{
SemVer 2.0 check against the credential's version bounds.
}

@defproc[(select-latest-entitlement
          [credentials (and/c (listof verified-credential?) pair?)])
         verified-credential?]{
Deterministic replacement among credentials actually received: highest
@tt{revision} for the same @tt{entitlement_id}. This is replacement,
not offline revocation.
}

@section{Issuing credentials}

@defmodule[permit/issuer]

The issuer surface is an explicit opt-in; the client facade above
never exports private-key operations.

@defproc[(generate-ed25519-keypair)
         (values pk-key? pk-key?)]{}
@defproc[(read-ed25519-private-key [source path-string?]) pk-key?]{}
@defproc[(read-ed25519-public-key [source path-string?]) pk-key?]{}
@defproc[(ed25519-private-key->der [key pk-key?]) bytes?]{}
@defproc[(ed25519-public-key->der [key pk-key?]) bytes?]{}
@defproc[(public-key->base64 [key pk-key?]) string?]{}

@defproc[(issued-credential? [value any/c]) boolean?]{
Recognizes the opaque result of @racket[issue-credential].
}

@defproc[(issue-credential [payload bytes?]
                           [private-key pk-key?]
                           [key-id string?]
                           [store trust-store?])
         issued-credential?]{
The safe issuance path: schema-validates the payload, pins issuer,
active key status, key purpose, and the key's issuance window, and
verifies the private key matches the trust-store public key. The
@racket[raco permit issue] command goes through this function;
@racket[raco permit sign] is the deliberate low-level escape hatch.
}

@defproc[(write-issued-credential [credential issued-credential?]
                                  [destination (or/c path-string? output-port?)])
         void?]{
Serializes an issued credential as its Protocol v1 JSON envelope. This is the
supported programmatic path from safe issuance to storage or delivery.
}

@section{Command line}

@verbatim|{raco permit keygen --private k.der --public pub.der \
           --trust-store trust.json --key-id license-2027 \
           --issuer com.example
raco permit issue  --key k.der --key-id license-2027 \
           --trust-store trust.json --payload ent.json \
           --output customer.permit.json
raco permit verify --trust-store trust.json \
           --credential customer.permit.json
raco permit check  --trust-store trust.json \
           --credential customer.permit.json \
           --product example-app --edition pro
raco permit inspect --credential customer.permit.json}|#

@tt{inspect} is deliberately labelled unverified; never authorize a
feature from inspected claims alone.

@section{Local trials and installation identity}

@defproc[(generate-installation-id) string?]{
A random, privacy-preserving installation identifier — not a hardware
fingerprint.
}

@defproc[(make-local-trial
          [#:duration-seconds duration-seconds exact-positive-integer? (* 14 24 60 60)]
          [#:at at string? (current-rfc3339)]
          [#:id id string? (generate-local-trial-id)])
         local-trial?]{}
@defproc[(evaluate-local-trial [trial local-trial?]
                               [#:at at string? (current-rfc3339)]
                               [#:extensions extensions (listof verified-credential?) '()]
                               [#:issuer issuer (or/c string? #f) #f]
                               [#:rollback-tolerance-seconds tolerance exact-nonnegative-integer? 300])
         local-trial-evaluation?]{
Evaluates the trial against the stored clock high-water mark and any
verified @tt{trial-extension} credentials. The result carries the
updated state to persist.
}

@defproc[(local-trial-evaluation-state [r local-trial-evaluation?]) local-trial?]{}
@defproc[(local-trial-evaluation-active? [r local-trial-evaluation?]) boolean?]{}
@defproc[(local-trial-evaluation-reason [r local-trial-evaluation?]) (or/c symbol? #f)]{}
@defproc[(local-trial-evaluation-remaining-seconds [r local-trial-evaluation?]) (or/c exact-integer? #f)]{}
@defproc[(local-trial->jsexpr [t local-trial?]) jsexpr?]{}
@defproc[(jsexpr->local-trial [v jsexpr?]) local-trial?]{}
@defproc[(write-local-trial [t local-trial?] [destination path-string?]) void?]{}
@defproc[(read-local-trial [source path-string?]) local-trial?]{

A local trial is signed nowhere — it is convenience state with a random
id and a last-seen clock high-water mark. That is nuisance resistance,
not tamper resistance; a user controlling the machine can reset it.
}
