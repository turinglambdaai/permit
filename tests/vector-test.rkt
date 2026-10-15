#lang racket/base

(require rackunit
         racket/file
         racket/runtime-path
         "../permit/main.rkt")

(define-runtime-path vector-root "../test-vectors/v1")
(define payload-path (build-path vector-root "entitlement-payload.json"))
(define credential-path (build-path vector-root "entitlement.permit.json"))
(define trust-path (build-path vector-root "trust-store.json"))

(define credential
  (verify-credential credential-path (read-trust-store trust-path)))

(check-equal? (verified-credential-id credential) "cred_vector_01")
(check-equal? (verified-credential-entitlement-id credential) "ent_vector_01")
(check-equal? (verified-credential-revision credential) 0)
(check-equal? (verified-credential-payload credential) (file->bytes payload-path))

(check-true
 (update-entitled? credential
                   "gptp-studio"
                   "2027-10-15T23:59:59Z"
                   #:at "2030-01-01T00:00:00Z"
                   #:version "2.0.0"))
(check-false
 (update-entitled? credential
                   "gptp-studio"
                   "2027-10-16T00:00:00Z"
                   #:at "2030-01-01T00:00:00Z"
                   #:version "2.0.0"))

;; Any payload-byte change invalidates the exact-byte signature.
(define envelope (read-envelope credential-path))
(check-false
 (verify-envelope-signature
  (struct-copy permit-envelope
               envelope
               [payload (bytes-append (permit-envelope-payload envelope) #" ")])
  (trust-key-public-key
   (trust-store-key (read-trust-store trust-path)
                    (permit-envelope-key-id envelope)))))
