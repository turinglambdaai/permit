#lang racket/base

(require json
         rackunit
         racket/port
         "../permit/credential.rkt"
         "../permit/crypto.rkt"
         "../permit/issuer.rkt"
         "../permit/policy.rkt"
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
(check-true (issued-credential? envelope))
(define serialized-envelope
  (call-with-output-bytes
   (lambda (out)
     (write-issued-credential envelope out))))
(check-equal? (verified-credential-id
               (verify-credential (open-input-bytes serialized-envelope) store))
              "cred_issue_test")
(check-exn exn:fail:contract?
           (lambda () (write-issued-credential 'not-a-credential (open-output-bytes))))
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

;; ---- rights snapshots (docs/decisions/0001) ----

;; A constructed snapshot is a complete, schema-valid payload that signs and
;; verifies through the safe path.
(define snapshot
  (entitlement-payload
   #:issuer "example.test"
   #:credential-id "cred_snapshot_0"
   #:entitlement-id "ent_snapshot"
   #:subject (subject #:type "organization" #:id "org_1" #:display "Org One")
   #:grants (list (grant #:products '("example-product")
                         #:edition "team"
                         #:features '("export")
                         #:capabilities (hasheq 'seats 5)))
   #:constraints (constraints #:updates-through "2027-12-31T23:59:59Z"
                              #:named-seats 5)
   #:issued-at "2026-06-01T00:00:00Z"))
(define snapshot-credential
  (verify-credential
   (issue-credential (payload->bytes snapshot) private-key "issuer-2026" store)
   store))
(check-equal? (verified-credential-id snapshot-credential) "cred_snapshot_0")
(check-equal? (verified-credential-entitlement-id snapshot-credential) "ent_snapshot")
(check-equal? (verified-credential-subject-display snapshot-credential) "Org One")
(check-equal? (verified-credential-channel snapshot-credential) "commercial")
(check-equal? (hash-ref snapshot 'revision) 0)
;; the closed field set is complete and nothing more
(check-equal? (sort (hash-keys snapshot) symbol<?)
              (sort '(protocol version type credential_id entitlement_id revision
                      issuer issued_at not_before subject channel grants
                      constraints extensions)
                    symbol<?))

;; trial snapshots default to the trial channel and must carry a use window
(check-equal?
 (hash-ref (entitlement-payload
            #:type "trial"
            #:issuer "example.test"
            #:credential-id "cred_trial"
            #:entitlement-id "ent_trial"
            #:subject (subject #:type "anonymous" #:id "anon_1")
            #:grants (list (grant #:products '("example-product") #:edition "pro"))
            #:constraints (constraints #:use-expires-at "2026-07-01T00:00:00Z")
            #:issued-at "2026-06-01T00:00:00Z")
           'channel)
 "trial")

;; construction validates: an invalid snapshot fails where it is built, not
;; inside the signer
(define (snapshot-with #:grants [grants (list (grant #:products '("p")))]
                      #:revision [revision 0])
  (entitlement-payload #:issuer "example.test"
                       #:credential-id "cred_bad"
                       #:entitlement-id "ent_bad"
                       #:revision revision
                       #:subject (subject #:type "person" #:id "p_1")
                       #:grants grants
                       #:issued-at "2026-06-01T00:00:00Z"))
(check-exn #rx"feature_policy"
           (lambda ()
             (snapshot-with #:grants (list (grant #:products '("p")
                                                 #:feature-policy "wildcard")))))
(check-exn #rx"scope must name"
           (lambda () (snapshot-with #:grants (list (grant)))))
(check-exn #rx"revision"
           (lambda () (snapshot-with #:revision -1)))
(check-exn #rx"at least one grant"
           (lambda () (snapshot-with #:grants '())))

;; successor: identity is inherited, revision advances, everything else
;; defaults to the previous snapshot unless replaced
(define renewal
  (successor-payload snapshot
                     #:credential-id "cred_snapshot_1"
                     #:issued-at "2027-06-01T00:00:00Z"
                     #:constraints (constraints #:updates-through "2028-12-31T23:59:59Z"
                                                #:named-seats 5)))
(check-equal? (hash-ref renewal 'entitlement_id) "ent_snapshot")
(check-equal? (hash-ref renewal 'revision) 1)
(check-equal? (hash-ref renewal 'issuer) "example.test")
(check-equal? (hash-ref renewal 'type) "entitlement")
(check-equal? (hash-ref renewal 'credential_id) "cred_snapshot_1")
(check-equal? (hash-ref renewal 'subject) (hash-ref snapshot 'subject))
(check-equal? (hash-ref renewal 'grants) (hash-ref snapshot 'grants))
(check-equal? (hash-ref renewal 'channel) (hash-ref snapshot 'channel))
(check-equal? (hash-ref (hash-ref renewal 'constraints) 'updates_through)
              "2028-12-31T23:59:59Z")
(check-equal? (hash-ref renewal 'not_before) 'null)
(check-equal? (verified-credential-entitlement-id
               (verify-credential
                (issue-credential (payload->bytes renewal) private-key "issuer-2026" store)
                store))
              "ent_snapshot")

;; a withdrawal is a successor whose use window has already closed
(define withdrawal
  (successor-payload renewal
                     #:credential-id "cred_snapshot_2"
                     #:issued-at "2027-07-01T00:00:00Z"
                     #:constraints (constraints #:use-expires-at "2027-07-01T00:00:00Z")))
(check-equal? (hash-ref withdrawal 'revision) 2)
(check-false
 (credential-usable?
  (verify-credential
   (issue-credential (payload->bytes withdrawal) private-key "issuer-2026" store)
   store)
  #:at "2027-08-01T00:00:00Z"))

;; successors need entitlement-like input
(check-exn #rx"unsupported credential type"
           (lambda ()
             (successor-payload (hasheq 'type "nonsense")
                                #:credential-id "x"
                                #:issued-at "2026-06-01T00:00:00Z")))

;; ---- typed issuance failures ----

(define (issue-reason thunk)
  (with-handlers ([exn:fail:permit:issue? exn:fail:permit-reason])
    (thunk)
    'no-failure))

(check-equal? (issue-reason
               (lambda () (issue-credential #"{\"protocol\":\"permit\"}" private-key "issuer-2026" store)))
              'schema)
(check-equal? (issue-reason
               (lambda () (issue-credential (payload (claims #:issuer "other.example"))
                                            private-key "issuer-2026" store)))
              'issuer)
(check-equal? (issue-reason
               (lambda () (issue-credential (payload (claims)) private-key "missing-key" store)))
              'key-unknown)
(check-equal? (issue-reason
               (lambda ()
                 (issue-credential (payload (claims)) private-key "issuer-2026"
                                   (trust-store-for #:status "retired"
                                                    #:not-after "2026-12-31T23:59:59Z"))))
              'key-status)
(check-equal? (issue-reason
               (lambda ()
                 (issue-credential (payload (claims #:issued-at "2027-01-01T00:00:00Z"))
                                   private-key "issuer-2026"
                                   (trust-store-for #:not-after "2026-12-31T23:59:59Z"))))
              'key-window)
(check-equal? (issue-reason
               (lambda ()
                 (issue-credential (payload (claims)) private-key "issuer-2026"
                                   (trust-store-for #:purposes '("activation")))))
              'key-purpose)
(check-equal? (issue-reason
               (lambda () (issue-credential (payload (claims)) other-private "issuer-2026" store)))
              'key-mismatch)
(check-equal? (issue-reason
               (lambda () (issue-credential (payload (claims)) private-key "issuer-2026" store)))
              'no-failure)
(check-equal? (sort issue-failure-reasons symbol<?)
              (sort '(schema issuer key-unknown key-status key-window key-purpose key-mismatch)
                    symbol<?))
;; typed failures stay exn:fail, so fail-closed callers keep working unchanged
(check-true (exn:fail? (with-handlers ([exn:fail? values])
                         (issue-credential #"{}" private-key "issuer-2026" store))))
