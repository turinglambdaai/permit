#lang racket/base

(require "crypto.rkt"
         "envelope.rkt"
         "schema.rkt"
         "trust.rkt")

(provide issue-credential
         generate-ed25519-keypair
         read-ed25519-private-key
         read-ed25519-public-key
         ed25519-private-key->der
         ed25519-public-key->der
         public-key->base64)

;; Safe issuer path: unlike low-level envelope signing, this checks that the
;; payload is schema-valid, belongs to the configured issuer, is allowed by
;; the selected active key, falls inside that key's issuance window, and was
;; signed by the private key corresponding to the trust-store public key.
(define (issue-credential payload private-key key-id store)
  (unless (bytes? payload)
    (raise-argument-error 'issue-credential "bytes?" payload))
  (unless (trust-store? store)
    (raise-argument-error 'issue-credential "trust-store?" store))
  (unless (and (string? key-id) (positive? (string-length key-id)))
    (raise-argument-error 'issue-credential "non-empty string?" key-id))

  (define claims (parse-credential-payload payload))
  (unless (equal? (hash-ref claims 'issuer) (trust-store-issuer store))
    (raise-arguments-error 'issue-credential
                           "credential issuer does not match trust store"
                           "credential issuer"
                           (hash-ref claims 'issuer)
                           "trust store issuer"
                           (trust-store-issuer store)))

  (define key (trust-store-key store key-id))
  (unless (equal? (trust-key-status key) "active")
    (raise-arguments-error 'issue-credential
                           "safe issuance requires an active signing key"
                           "key_id"
                           key-id
                           "status"
                           (trust-key-status key)))
  (trust-key-authorize-issued-at! key (hash-ref claims 'issued_at))
  (trust-key-authorize-type! key (hash-ref claims 'type))

  (define derived-public
    (ed25519-private-key->public-key private-key))
  (unless (bytes=? (ed25519-public-key->der derived-public)
                   (ed25519-public-key->der (trust-key-public-key key)))
    (raise-arguments-error 'issue-credential
                           "private key does not match trust-store public key"
                           "key_id"
                           key-id))

  (make-signed-envelope key-id payload private-key))
