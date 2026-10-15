#lang racket/base

(require "envelope.rkt"
         "private/time.rkt"
         "schema.rkt"
         "trust.rkt")

(provide (struct-out verified-credential)
         verify-credential
         verified-credential-type
         verified-credential-id)

(struct verified-credential (claims payload key-id) #:transparent)

(define (verify-credential envelope-or-source store #:at [at (current-rfc3339)])
  (define envelope
    (if (permit-envelope? envelope-or-source)
        envelope-or-source
        (read-envelope envelope-or-source)))
  (define key (trust-store-key store (permit-envelope-key-id envelope) #:at at))
  (unless (verify-envelope-signature envelope (trust-key-public-key key))
    (raise-arguments-error 'verify-credential
                           "invalid Ed25519 signature"
                           "key_id"
                           (permit-envelope-key-id envelope)))
  (define claims (parse-credential-payload (permit-envelope-payload envelope)))
  (unless (equal? (hash-ref claims 'issuer) (trust-store-issuer store))
    (raise-arguments-error 'verify-credential
                           "credential issuer does not match trust store"
                           "credential issuer"
                           (hash-ref claims 'issuer)
                           "trust store issuer"
                           (trust-store-issuer store)))
  (verified-credential claims (permit-envelope-payload envelope) (permit-envelope-key-id envelope)))

(define (verified-credential-type credential)
  (hash-ref (verified-credential-claims credential) 'type))

(define (verified-credential-id credential)
  (hash-ref (verified-credential-claims credential) 'credential_id))
