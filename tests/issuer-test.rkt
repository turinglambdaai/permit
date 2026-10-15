#lang racket/base

(require json
         rackunit
         racket/port
         "../permit/credential.rkt"
         "../permit/crypto.rkt"
         "../permit/issuer.rkt"
         "../permit/trust.rkt")

(define-values (private-key public-key)
  (generate-ed25519-keypair))

(define (trust-store-for #:status [status "active"]
                         #:purposes [purposes '("entitlement")]
                         #:not-before [not-before 'null]
                         #:not-after [not-after 'null]
                         #:public-key [key public-key])
  (jsexpr->trust-store
   (hasheq 'protocol "permit-trust-store"
           'version 1
           'issuer "example.test"
           'keys
           (hasheq 'issuer-2026
                   (hasheq 'algorithm "Ed25519"
                           'public_key (public-key->base64 key)
                           'status status
                           'purposes purposes
                           'not_before not-before
                           'not_after not-after)))))

(define (claims #:issuer [issuer "example.test"]
                #:issued-at [issued-at "2026-06-01T00:00:00Z"])
  (hasheq
   'protocol "permit"
   'version 1
   'type "entitlement"
   'credential_id "cred_issue_test"
   'entitlement_id "ent_issue_test"
   'revision 0
   'issuer issuer
   'issued_at issued-at
   'not_before 'null
   'subject (hasheq 'type "person" 'id "cus_test" 'display 'null)
   'channel "commercial"
   'grants
   (list
    (hasheq 'scope (hasheq 'products '("example-product")
                            'product_families '())
            'edition "pro"
            'feature_policy "explicit"
            'features '("export")
            'addons '()
            'capabilities (hasheq)))
   'constraints
   (hasheq 'use_expires_at 'null
           'updates_through 'null
           'features_through 'null
           'version_policy (hasheq 'min 'null 'max 'null)
           'limits (hasheq 'named_seats 1
                           'device_activations 1
                           'concurrent_seats 'null)
           'installation_id 'null
           'activation_required #f)
   'extensions (hasheq)))

(define (payload value)
  (call-with-output-bytes
   (lambda (out) (write-json value out))))

(define store (trust-store-for))
(define envelope
  (issue-credential (payload (claims))
                    private-key
                    "issuer-2026"
                    store))
(define verified (verify-credential envelope store))
(check-equal? (verified-credential-id verified) "cred_issue_test")
(check-equal? (verified-credential-entitlement-id verified) "ent_issue_test")
(check-equal? (verified-credential-subject-id verified) "cus_test")
(check-equal? (verified-credential-subject-display verified) #f)
(check-equal? (verified-credential-channel verified) "commercial")
(check-equal? (verified-credential-use-expires-at verified) #f)

;; The safe issuer path refuses a private key that does not correspond to the
;; selected trust-store public key.
(define-values (other-private other-public)
  (generate-ed25519-keypair))
(check-exn #rx"private key does not match"
           (lambda ()
             (issue-credential (payload (claims))
                               other-private
                               "issuer-2026"
                               store)))

;; The signed issuer is part of the protected payload and must agree with the
;; trust domain used for issuance.
(check-exn #rx"issuer does not match"
           (lambda ()
             (issue-credential (payload (claims #:issuer "other.example"))
                               private-key
                               "issuer-2026"
                               store)))

;; Online lease keys cannot mint durable entitlements.
(check-exn #rx"not authorized for credential type"
           (lambda ()
             (issue-credential (payload (claims))
                               private-key
                               "issuer-2026"
                               (trust-store-for #:purposes '("activation")))))

;; Retired keys remain useful for verifying historical credentials but are not
;; accepted by the safe path for new issuance.
(check-exn #rx"active signing key"
           (lambda ()
             (issue-credential
              (payload (claims))
              private-key
              "issuer-2026"
              (trust-store-for #:status "retired"
                               #:not-after "2026-12-31T23:59:59Z"))))

;; Even an active key cannot issue outside its authenticated issuance window.
(check-exn #rx"issuance window"
           (lambda ()
             (issue-credential
              (payload (claims #:issued-at "2027-01-01T00:00:00Z"))
              private-key
              "issuer-2026"
              (trust-store-for #:not-after "2026-12-31T23:59:59Z"))))
