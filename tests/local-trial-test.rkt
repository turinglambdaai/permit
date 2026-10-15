#lang racket/base

(require json
         rackunit
         racket/port
         "../permit/main.rkt")

(define start "2026-01-01T00:00:00Z")
(define trial
  (make-local-trial #:duration-seconds 120
                    #:at start
                    #:id "trial_test_01"))

(check-equal? (local-trial-started-at trial) start)
(check-equal? (local-trial-expires-at trial) "2026-01-01T00:02:00Z")
(check-true (regexp-match? #px"^ins_[0-9a-f]{32}$" (generate-installation-id)))
(check-true (regexp-match? #px"^trial_[0-9a-f]{32}$" (generate-local-trial-id)))

(define encoded (local-trial->jsexpr trial))
(check-equal? (jsexpr->local-trial encoded) trial)

(define out (open-output-string))
(write-local-trial trial out)
(check-equal? (read-local-trial (open-input-string (get-output-string out))) trial)

(define active
  (evaluate-local-trial trial #:at "2026-01-01T00:01:00Z"))
(check-true (local-trial-evaluation-active? active))
(check-equal? (local-trial-evaluation-reason active) 'active)
(check-equal? (local-trial-evaluation-remaining-seconds active) 60)
(check-equal? (local-trial-last-seen-at (local-trial-evaluation-state active))
              "2026-01-01T00:01:00Z")

;; Expiry is inclusive, matching Permit's signed use_expires_at semantics.
(define last-instant
  (evaluate-local-trial trial #:at "2026-01-01T00:02:00Z"))
(check-true (local-trial-evaluation-active? last-instant))
(check-equal? (local-trial-evaluation-remaining-seconds last-instant) 0)

(define expired
  (evaluate-local-trial trial #:at "2026-01-01T00:02:01Z"))
(check-false (local-trial-evaluation-active? expired))
(check-equal? (local-trial-evaluation-reason expired) 'expired)

;; The persisted high-water mark catches obvious wall-clock rollback. It is
;; nuisance resistance only: a local attacker can still edit or delete state.
(define touched (local-trial-evaluation-state
                 (evaluate-local-trial trial #:at "2026-01-01T00:01:30Z")))
(define rollback
  (evaluate-local-trial touched
                        #:at "2026-01-01T00:01:00Z"
                        #:rollback-tolerance-seconds 0))
(check-false (local-trial-evaluation-active? rollback))
(check-equal? (local-trial-evaluation-reason rollback) 'clock-rollback)
(check-equal? (local-trial-last-seen-at (local-trial-evaluation-state rollback))
              "2026-01-01T00:01:30Z")

(define-values (test-private-key test-public-key)
  (generate-ed25519-keypair))

(define test-store
  (jsexpr->trust-store
   (hasheq 'protocol "permit-trust-store"
           'version 1
           'issuer "example.test"
           'keys
           (hasheq 'trial-test
                   (hasheq 'algorithm "Ed25519"
                           'public_key (public-key->base64 test-public-key)
                           'status "active"
                           'purposes '("trial-extension")
                           'not_before 'null
                           'not_after 'null)))))

(define (extension id trial-id issued-at expires-at)
  (define claims
    (hasheq 'protocol "permit"
            'version 1
            'type "trial-extension"
            'credential_id id
            'trial_id trial-id
            'issuer "example.test"
            'issued_at issued-at
            'not_before 'null
            'use_expires_at expires-at
            'extensions (hasheq)))
  (define payload
    (call-with-output-bytes
     (lambda (out) (write-json claims out))))
  (verify-credential
   (make-signed-envelope "trial-test" payload test-private-key)
   test-store))

(define good-extension
  (extension "ext_01"
             "trial_test_01"
             "2026-01-01T00:01:00Z"
             "2026-01-01T00:05:00Z"))
(define wrong-trial-extension
  (extension "ext_other"
             "trial_other"
             "2026-01-01T00:01:00Z"
             "2026-01-01T00:10:00Z"))

(check-exn #rx"issuer is required"
           (lambda ()
             (evaluate-local-trial trial
                                   #:at "2026-01-01T00:03:00Z"
                                   #:extensions (list good-extension))))

(define extended
  (evaluate-local-trial trial
                        #:at "2026-01-01T00:03:00Z"
                        #:issuer "example.test"
                        #:extensions (list good-extension good-extension)))
(check-true (local-trial-evaluation-active? extended))
(check-equal? (local-trial-evaluation-expires-at extended)
              "2026-01-01T00:05:00Z")
(check-equal? (local-trial-evaluation-applied-extension-ids extended)
              '("ext_01"))

(define not-extended
  (evaluate-local-trial trial
                        #:at "2026-01-01T00:03:00Z"
                        #:issuer "example.test"
                        #:extensions (list wrong-trial-extension)))
(check-false (local-trial-evaluation-active? not-extended))
(check-equal? (local-trial-evaluation-reason not-extended) 'expired)

(define wrong-issuer
  (evaluate-local-trial trial
                        #:at "2026-01-01T00:03:00Z"
                        #:issuer "another-issuer"
                        #:extensions (list good-extension)))
(check-false (local-trial-evaluation-active? wrong-issuer))

(check-exn #rx"duplicate JSON object member"
           (lambda ()
             (read-local-trial
              (open-input-string
               "{\"protocol\":\"permit-local-trial\",\"protocol\":\"permit-local-trial\"}"))))
