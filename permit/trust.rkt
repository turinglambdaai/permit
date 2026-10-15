#lang racket/base

(require json
         racket/list
         "crypto.rkt"
         "private/time.rkt")

(provide (struct-out trust-key)
         (struct-out trust-store)
         jsexpr->trust-store
         read-trust-store
         trust-store-key)

(struct trust-key (id public-key status not-before not-after) #:transparent)
(struct trust-store (issuer keys) #:transparent)

(define top-fields '(issuer keys protocol version))
(define key-fields '(algorithm not_after not_before public_key status))
(define allowed-statuses '("active" "next" "retired" "revoked"))

(define (exact-fields! who value expected label)
  (unless (hash? value)
    (raise-arguments-error who (string-append label " must be a JSON object") "value" value))
  (define actual (sort (hash-keys value) symbol<?))
  (unless (equal? actual expected)
    (raise-arguments-error who
                           (string-append "unexpected " label " fields")
                           "expected"
                           expected
                           "actual"
                           actual)))

(define (nullable-time? value)
  (or (eq? value 'null) (rfc3339-utc? value)))

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
  (unless (hash? key-values)
    (raise-arguments-error who "keys must be a JSON object" "value" key-values))
  (define keys
    (for/hash ([(raw-id entry) (in-hash key-values)])
      (define id (symbol->string raw-id))
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
      (define not-before (hash-ref entry 'not_before #f))
      (define not-after (hash-ref entry 'not_after #f))
      (unless (nullable-time? not-before)
        (raise-arguments-error who "invalid key not_before" "key_id" id "value" not-before))
      (unless (nullable-time? not-after)
        (raise-arguments-error who "invalid key not_after" "key_id" id "value" not-after))
      (values id
              (trust-key id
                         (base64->public-key (hash-ref entry 'public_key #f))
                         status
                         not-before
                         not-after))))
  (trust-store issuer keys))

(define (read-trust-store source)
  (define value
    (cond
      [(input-port? source) (read-json source)]
      [(path-string? source) (call-with-input-file source read-json)]
      [else (raise-argument-error 'read-trust-store "(or/c input-port? path-string?)" source)]))
  (jsexpr->trust-store value))

(define (trust-store-key store key-id #:at [at (current-rfc3339)])
  (unless (trust-store? store)
    (raise-argument-error 'trust-store-key "trust-store?" store))
  (unless (rfc3339-utc? at)
    (raise-argument-error 'trust-store-key "canonical RFC 3339 UTC timestamp" at))
  (define key (hash-ref (trust-store-keys store) key-id #f))
  (unless key
    (raise-arguments-error 'trust-store-key "unknown key_id" "key_id" key-id))
  (when (equal? (trust-key-status key) "revoked")
    (raise-arguments-error 'trust-store-key "signing key is revoked" "key_id" key-id))
  (define not-before (trust-key-not-before key))
  (define not-after (trust-key-not-after key))
  (when (and (not (eq? not-before 'null)) (not (rfc3339<=? not-before at)))
    (raise-arguments-error 'trust-store-key
                           "signing key is not active yet"
                           "key_id"
                           key-id
                           "not_before"
                           not-before))
  (when (and (not (eq? not-after 'null)) (not (rfc3339<=? at not-after)))
    (raise-arguments-error 'trust-store-key
                           "signing key is no longer trusted"
                           "key_id"
                           key-id
                           "not_after"
                           not-after))
  key)
