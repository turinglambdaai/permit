#lang racket/base

(require racket/list
         "envelope.rkt"
         "schema.rkt"
         "trust.rkt")

(provide verified-credential?
         verified-credential-claims
         verified-credential-payload
         verified-credential-key-id
         verify-credential
         verified-credential-type
         verified-credential-id
         verified-credential-entitlement-id
         verified-credential-revision
         select-latest-entitlement)

(struct verified-credential (claims payload key-id) #:transparent)

(define (verify-credential envelope-or-source store)
  (define envelope
    (if (permit-envelope? envelope-or-source)
        envelope-or-source
        (read-envelope envelope-or-source)))
  ;; key_id is outside the signed payload, so it may select a public key but
  ;; cannot authorize anything by itself.
  (define key (trust-store-key store (permit-envelope-key-id envelope)))
  (unless (verify-envelope-signature envelope (trust-key-public-key key))
    (raise-arguments-error 'verify-credential
                           "invalid Ed25519 signature"
                           "key_id"
                           (permit-envelope-key-id envelope)))
  ;; Only cross the semantic parsing boundary after the exact payload bytes
  ;; have been authenticated.
  (define claims (parse-credential-payload (permit-envelope-payload envelope)))
  (unless (equal? (hash-ref claims 'issuer) (trust-store-issuer store))
    (raise-arguments-error 'verify-credential
                           "credential issuer does not match trust store"
                           "credential issuer"
                           (hash-ref claims 'issuer)
                           "trust store issuer"
                           (trust-store-issuer store)))
  (trust-key-authorize-issued-at! key (hash-ref claims 'issued_at))
  (trust-key-authorize-type! key (hash-ref claims 'type))
  (verified-credential claims (permit-envelope-payload envelope) (permit-envelope-key-id envelope)))

(define (verified-credential-type credential)
  (hash-ref (verified-credential-claims credential) 'type))

(define (verified-credential-id credential)
  (hash-ref (verified-credential-claims credential) 'credential_id))

(define (verified-credential-entitlement-id credential)
  (define claims (verified-credential-claims credential))
  (hash-ref claims 'entitlement_id #f))

(define (verified-credential-revision credential)
  (define claims (verified-credential-claims credential))
  (unless (entitlement-like? claims)
    (raise-arguments-error 'verified-credential-revision
                           "credential has no entitlement revision"
                           "type"
                           (hash-ref claims 'type #f)))
  (hash-ref claims 'revision))

;; Select the newest presented statement for one logical entitlement lineage.
;; This is intentionally not revocation: a client that never receives a newer
;; revision cannot infer that an older offline credential was superseded.
(define (select-latest-entitlement credentials)
  (unless (and (list? credentials) (pair? credentials) (andmap verified-credential? credentials))
    (raise-argument-error 'select-latest-entitlement
                          "(and/c (listof verified-credential?) pair?)"
                          credentials))
  (for ([credential (in-list credentials)])
    (unless (entitlement-like? (verified-credential-claims credential))
      (raise-arguments-error 'select-latest-entitlement
                             "all credentials must be entitlement or trial credentials"
                             "type"
                             (verified-credential-type credential))))
  (define entitlement-id (verified-credential-entitlement-id (car credentials)))
  (define issuer (hash-ref (verified-credential-claims (car credentials)) 'issuer))
  (unless (andmap (lambda (credential)
                    (and (equal? (verified-credential-entitlement-id credential) entitlement-id)
                         (equal? (hash-ref (verified-credential-claims credential) 'issuer)
                                 issuer)))
                  credentials)
    (raise-arguments-error 'select-latest-entitlement
                           "credentials belong to different entitlement lineages"
                           "issuer"
                           issuer
                           "entitlement_ids"
                           (map verified-credential-entitlement-id credentials)))
  (define highest
    (apply max (map verified-credential-revision credentials)))
  (define candidates
    (filter (lambda (credential) (= (verified-credential-revision credential) highest))
            credentials))
  (define first-candidate (car candidates))
  (unless (andmap (lambda (candidate)
                    (bytes=? (verified-credential-payload candidate)
                             (verified-credential-payload first-candidate)))
                  (cdr candidates))
    (raise-arguments-error 'select-latest-entitlement
                           "conflicting credentials share the highest revision"
                           "entitlement_id"
                           entitlement-id
                           "revision"
                           highest))
  first-candidate)
