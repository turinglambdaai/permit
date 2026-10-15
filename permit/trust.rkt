#lang racket/base

(require json
         racket/list
         "crypto.rkt"
         "private/time.rkt")

(provide (struct-out trust-key)
         (struct-out trust-store)
         jsexpr->trust-store
         read-trust-store
         trust-store-key
         trust-key-valid-for-issued-at?
         trust-key-authorize-issued-at!)

(struct trust-key (id public-key status not-before not-after) #:transparent)
(struct trust-store (issuer keys) #:transparent)

(define top-fields '(issuer keys protocol version))
(define key-fields '(algorithm not_after not_before public_key status))
(define allowed-statuses '("active" "next" "retired" "revoked"))

(define (exact-fields! who value expected label)
  (unless (hash? value)
    (raise-arguments-error who (string-append label " must be a JSON object") "value" value))
  (define actual (sort (hash-keys value) symbol<?))
  (define wanted (sort expected symbol<?))
  (unless (equal? actual wanted)
    (raise-arguments-error who
                           (string-append "unexpected " label " fields")
                           "expected"
                           wanted
                           "actual"
                           actual)))

(define (nullable-time? value)
  (or (eq? value 'null) (rfc3339-utc? value)))

(define (read-complete-json who in)
  (define value (read-json in))
  (define trailing (read-json in))
  (unless (eof-object? trailing)
    (raise-arguments-error who "input must contain exactly one JSON value"))
  value)

(define (jsexpr->trust-store value)
  (define who 'jsexpr->trust-store)
  (exact-fields! who value top-fields "trust store")
  (unless (equal? (hash-ref value 'protocol #f) "permit-trust-store")
    (raise-arguments-error who "invalid protocol" "value" (hash-ref value 'protocol #f)))
  (unless (equal? (hash-ref value 'version #f) 1)
    (raise-arguments-error who "unsupported version" "value" (hash-ref value 'version #f)))
  (define issuer (hash-ref value 'issuer #f))
  (unless (and (string? issuer) (positive? (string-length issuer)))
    (raise-arguments-error who "invalid issuer" "value" issuer))
  (define key-values (hash-ref value 'keys #f))
  (unless (and (hash? key-values) (positive? (hash-count key-values)))
    (raise-arguments-error who "keys must be a non-empty JSON object" "value" key-values))
  (define seen-public-keys (make-hash))
  (define keys
    (for/hash ([(raw-id entry) (in-hash key-values)])
      (unless (symbol? raw-id)
        (raise-arguments-error who "trust-store key ids must be JSON object keys" "key_id" raw-id))
      (define id (symbol->string raw-id))
      (unless (positive? (string-length id))
        (raise-arguments-error who "key_id must be non-empty" "key_id" id))
      (exact-fields! who entry key-fields "trust key")
      (unless (equal? (hash-ref entry 'algorithm #f) "Ed25519")
        (raise-arguments-error who
                               "unsupported key algorithm"
                               "key_id"
                               id
                               "algorithm"
                               (hash-ref entry 'algorithm #f)))
      (define status (hash-ref entry 'status #f))
      (unless (member status allowed-statuses)
        (raise-arguments-error who "invalid key status" "key_id" id "status" status))
      (define public-key-text (hash-ref entry 'public_key #f))
      (unless (and (string? public-key-text) (positive? (string-length public-key-text)))
        (raise-arguments-error who "invalid public_key" "key_id" id "value" public-key-text))
      (define prior-id (hash-ref seen-public-keys public-key-text #f))
      (when prior-id
        (raise-arguments-error who
                               "the same public key must not appear under multiple key ids"
                               "key_id"
                               id
                               "previous_key_id"
                               prior-id))
      (hash-set! seen-public-keys public-key-text id)
      (define not-before (hash-ref entry 'not_before #f))
      (define not-after (hash-ref entry 'not_after #f))
      (unless (nullable-time? not-before)
        (raise-arguments-error who "invalid key not_before" "key_id" id "value" not-before))
      (unless (nullable-time? not-after)
        (raise-arguments-error who "invalid key not_after" "key_id" id "value" not-after))
      (when (and (not (eq? not-before 'null))
                 (not (eq? not-after 'null))
                 (not (rfc3339<=? not-before not-after)))
        (raise-arguments-error who
                               "trust-key not_before must not exceed not_after"
                               "key_id"
                               id
                               "not_before"
                               not-before
                               "not_after"
                               not-after))
      (when (and (equal? status "next") (eq? not-before 'null))
        (raise-arguments-error who
                               "next key requires a not_before issuance boundary"
                               "key_id"
                               id))
      (when (and (equal? status "retired") (eq? not-after 'null))
        (raise-arguments-error who
                               "retired key requires a not_after issuance boundary"
                               "key_id"
                               id))
      (values id
              (trust-key id
                         (base64->public-key public-key-text)
                         status
                         not-before
                         not-after))))
  (trust-store issuer keys))

(define (read-trust-store source)
  (define value
    (cond
      [(input-port? source) (read-complete-json 'read-trust-store source)]
      [(path-string? source)
       (call-with-input-file source
         (lambda (in) (read-complete-json 'read-trust-store in)))]
      [else (raise-argument-error 'read-trust-store "(or/c input-port? path-string?)" source)]))
  (jsexpr->trust-store value))

(define (trust-store-key store key-id)
  (unless (trust-store? store)
    (raise-argument-error 'trust-store-key "trust-store?" store))
  (unless (and (string? key-id) (positive? (string-length key-id)))
    (raise-argument-error 'trust-store-key "non-empty string?" key-id))
  (define key (hash-ref (trust-store-keys store) key-id #f))
  (unless key
    (raise-arguments-error 'trust-store-key "unknown key_id" "key_id" key-id))
  (when (equal? (trust-key-status key) "revoked")
    (raise-arguments-error 'trust-store-key "signing key is revoked" "key_id" key-id))
  key)

;; Key windows constrain when a credential may have been signed, not when a
;; client happens to verify it. Otherwise a perpetual entitlement would stop
;; verifying when an old signing key reaches its issuance cutoff.
(define (trust-key-valid-for-issued-at? key issued-at)
  (unless (trust-key? key)
    (raise-argument-error 'trust-key-valid-for-issued-at? "trust-key?" key))
  (unless (rfc3339-utc? issued-at)
    (raise-argument-error 'trust-key-valid-for-issued-at?
                          "canonical RFC 3339 UTC timestamp"
                          issued-at))
  (define not-before (trust-key-not-before key))
  (define not-after (trust-key-not-after key))
  (and (or (eq? not-before 'null) (rfc3339<=? not-before issued-at))
       (or (eq? not-after 'null) (rfc3339<=? issued-at not-after))))

(define (trust-key-authorize-issued-at! key issued-at)
  (unless (trust-key-valid-for-issued-at? key issued-at)
    (raise-arguments-error 'verify-credential
                           "credential issued_at falls outside signing-key issuance window"
                           "key_id"
                           (trust-key-id key)
                           "issued_at"
                           issued-at
                           "key_not_before"
                           (trust-key-not-before key)
                           "key_not_after"
                           (trust-key-not-after key)))
  key)
