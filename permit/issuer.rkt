#lang racket/base

(require "crypto.rkt"
         "envelope.rkt"
         "failure.rkt"
         "schema.rkt"
         "snapshot.rkt"
         "trust.rkt")

(provide issued-credential?
         issue-credential
         write-issued-credential
         (struct-out exn:fail:permit)
         (struct-out exn:fail:permit:issue)
         issue-failure-reasons
         generate-ed25519-keypair
         read-ed25519-private-key
         read-ed25519-public-key
         ed25519-private-key->der
         ed25519-public-key->der
         public-key->base64
         ;; an issuer adapter needs the trust store too; re-exported so it
         ;; requires only this module
         trust-store?
         read-trust-store
         jsexpr->trust-store
         ;; rights snapshots (docs/decisions/0001)
         subject
         grant
         constraints
         entitlement-payload
         successor-payload
         payload->bytes)

;; Issued credentials remain opaque to callers. The issuer surface exposes the
;; predicate and serializer needed to persist or deliver one without exposing
;; raw envelope constructors as a second signing path.
(define issued-credential? permit-envelope?)

(define (write-issued-credential credential destination)
  (unless (issued-credential? credential)
    (raise-argument-error 'write-issued-credential "issued-credential?" credential))
  (write-envelope credential destination))

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

  (define claims
    (rewrap-as-issue-error 'schema (lambda () (parse-credential-payload payload))))
  (unless (equal? (hash-ref claims 'issuer) (trust-store-issuer store))
    (raise-issue-error 'issuer
                       "credential issuer does not match trust store"
                       "credential issuer"
                       (hash-ref claims 'issuer)
                       "trust store issuer"
                       (trust-store-issuer store)))

  (define key (hash-ref (trust-store-keys store) key-id #f))
  (unless key
    (raise-issue-error 'key-unknown "key_id is not in the trust store" "key_id" key-id))
  (unless (equal? (trust-key-status key) "active")
    (raise-issue-error 'key-status
                       "safe issuance requires an active signing key"
                       "key_id"
                       key-id
                       "status"
                       (trust-key-status key)))
  (define issued-at (hash-ref claims 'issued_at))
  (unless (trust-key-valid-for-issued-at? key issued-at)
    (raise-issue-error 'key-window
                       "credential issued_at falls outside signing-key issuance window"
                       "key_id"
                       key-id
                       "issued_at"
                       issued-at
                       "key_not_before"
                       (trust-key-not-before key)
                       "key_not_after"
                       (trust-key-not-after key)))
  (define type (hash-ref claims 'type))
  (unless (member type (trust-key-purposes key))
    (raise-issue-error 'key-purpose
                       "signing key is not authorized for credential type"
                       "key_id"
                       key-id
                       "credential_type"
                       type
                       "allowed_purposes"
                       (trust-key-purposes key)))

  (define derived-public
    (ed25519-private-key->public-key private-key))
  (unless (bytes=? (ed25519-public-key->der derived-public)
                   (ed25519-public-key->der (trust-key-public-key key)))
    (raise-issue-error 'key-mismatch
                       "private key does not match trust-store public key"
                       "key_id"
                       key-id))

  (make-signed-envelope key-id payload private-key))
