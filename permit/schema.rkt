#lang racket/base

(require json
         racket/list
         racket/port
         racket/string
         "private/time.rkt")

(provide parse-credential-payload
         validate-credential-claims
         entitlement-like?
         activation-claims?)

(define common-fields
  '(channel constraints
            credential_id
            extensions
            grants
            issued_at
            issuer
            not_before
            protocol
            subject
            type
            version))
(define activation-fields
  '(credential_id entitlement_id
                  extensions
                  installation_id
                  issued_at
                  issuer
                  lease_id
                  not_before
                  offline_grace_seconds
                  protocol
                  type
                  valid_until
                  version))
(define grant-fields '(addons capabilities edition features scope))
(define scope-fields '(product_families products))
(define constraints-fields
  '(activation_required features_through
                        installation_id
                        limits
                        updates_through
                        use_expires_at
                        version_policy))
(define limits-fields '(concurrent_seats device_activations named_seats))
(define version-policy-fields '(max min))
(define subject-fields '(display id type))

(define (fail who message . fields)
  (apply raise-arguments-error who message fields))

(define (expect who predicate description value label)
  (unless (predicate value)
    (fail who (string-append "invalid " label) "expected" description "value" value)))

(define (non-empty-string? value)
  (and (string? value) (positive? (string-length value))))

(define (string-list? value)
  (and (list? value) (andmap non-empty-string? value)))

(define (nullable predicate)
  (lambda (value) (or (eq? value 'null) (predicate value))))

(define (exact-fields! who value expected label)
  (expect who hash? "JSON object" value label)
  (define actual (sort (hash-keys value) symbol<?))
  (unless (equal? actual expected)
    (fail who (string-append "unexpected " label " fields") "expected" expected "actual" actual)))

(define (validate-subject who value)
  (exact-fields! who value subject-fields "subject")
  (expect who non-empty-string? "non-empty string" (hash-ref value 'type #f) "subject.type")
  (expect who non-empty-string? "non-empty string" (hash-ref value 'id #f) "subject.id")
  (expect who (nullable string?) "string or null" (hash-ref value 'display #f) "subject.display"))

(define (validate-scope who value)
  (exact-fields! who value scope-fields "scope")
  (expect who string-list? "list of strings" (hash-ref value 'products #f) "scope.products")
  (expect who
          string-list?
          "list of strings"
          (hash-ref value 'product_families #f)
          "scope.product_families")
  (when (and (null? (hash-ref value 'products)) (null? (hash-ref value 'product_families)))
    (fail who "scope must name a product or product family" "scope" value)))

(define (scalar-capability? value)
  (or (string? value) (boolean? value) (exact-integer? value) (real? value)))

(define (validate-grant who value)
  (exact-fields! who value grant-fields "grant")
  (validate-scope who (hash-ref value 'scope #f))
  (expect who non-empty-string? "non-empty string" (hash-ref value 'edition #f) "grant.edition")
  (expect who string-list? "list of strings" (hash-ref value 'features #f) "grant.features")
  (expect who string-list? "list of strings" (hash-ref value 'addons #f) "grant.addons")
  (define capabilities (hash-ref value 'capabilities #f))
  (expect who hash? "JSON object" capabilities "grant.capabilities")
  (for ([(name value) (in-hash capabilities)])
    (expect who symbol? "JSON object key" name "capability name")
    (expect who scalar-capability? "string, boolean, or number" value "capability value")))

(define (validate-constraints who value)
  (exact-fields! who value constraints-fields "constraints")
  (for ([name (in-list '(use_expires_at updates_through features_through))])
    (expect who
            (nullable rfc3339-utc?)
            "canonical UTC timestamp or null"
            (hash-ref value name #f)
            (format "constraints.~a" name)))
  (expect who
          (nullable non-empty-string?)
          "string or null"
          (hash-ref value 'installation_id #f)
          "constraints.installation_id")
  (expect who
          boolean?
          "boolean"
          (hash-ref value 'activation_required #f)
          "constraints.activation_required")
  (define limits (hash-ref value 'limits #f))
  (exact-fields! who limits limits-fields "constraints.limits")
  (for ([name (in-list limits-fields)])
    (expect who
            (nullable exact-nonnegative-integer?)
            "non-negative integer or null"
            (hash-ref limits name #f)
            (format "constraints.limits.~a" name)))
  (define versions (hash-ref value 'version_policy #f))
  (exact-fields! who versions version-policy-fields "constraints.version_policy")
  (for ([name (in-list version-policy-fields)])
    (expect who
            (nullable non-empty-string?)
            "string or null"
            (hash-ref versions name #f)
            (format "constraints.version_policy.~a" name))))

(define (validate-common who claims)
  (exact-fields! who claims common-fields "credential")
  (unless (equal? (hash-ref claims 'protocol #f) "permit")
    (fail who "invalid protocol" "value" (hash-ref claims 'protocol #f)))
  (unless (equal? (hash-ref claims 'version #f) 1)
    (fail who "unsupported protocol version" "value" (hash-ref claims 'version #f)))
  (expect who
          non-empty-string?
          "non-empty string"
          (hash-ref claims 'credential_id #f)
          "credential_id")
  (expect who non-empty-string? "non-empty string" (hash-ref claims 'issuer #f) "issuer")
  (expect who rfc3339-utc? "canonical UTC timestamp" (hash-ref claims 'issued_at #f) "issued_at")
  (expect who
          (nullable rfc3339-utc?)
          "canonical UTC timestamp or null"
          (hash-ref claims 'not_before #f)
          "not_before")
  (validate-subject who (hash-ref claims 'subject #f))
  (expect who non-empty-string? "non-empty string" (hash-ref claims 'channel #f) "channel")
  (define grants (hash-ref claims 'grants #f))
  (expect who list? "list" grants "grants")
  (when (null? grants)
    (fail who "credential must contain at least one grant" "grants" grants))
  (for ([grant (in-list grants)])
    (validate-grant who grant))
  (validate-constraints who (hash-ref claims 'constraints #f))
  (expect who hash? "JSON object" (hash-ref claims 'extensions #f) "extensions"))

(define (validate-activation who claims)
  (exact-fields! who claims activation-fields "activation credential")
  (unless (equal? (hash-ref claims 'protocol #f) "permit")
    (fail who "invalid protocol" "value" (hash-ref claims 'protocol #f)))
  (unless (equal? (hash-ref claims 'version #f) 1)
    (fail who "unsupported protocol version" "value" (hash-ref claims 'version #f)))
  (for ([name (in-list '(credential_id entitlement_id installation_id issuer lease_id))])
    (expect who non-empty-string? "non-empty string" (hash-ref claims name #f) (symbol->string name)))
  (for ([name (in-list '(issued_at valid_until))])
    (expect who
            rfc3339-utc?
            "canonical UTC timestamp"
            (hash-ref claims name #f)
            (symbol->string name)))
  (expect who
          (nullable rfc3339-utc?)
          "canonical UTC timestamp or null"
          (hash-ref claims 'not_before #f)
          "not_before")
  (expect who
          exact-nonnegative-integer?
          "non-negative integer"
          (hash-ref claims 'offline_grace_seconds #f)
          "offline_grace_seconds")
  (expect who hash? "JSON object" (hash-ref claims 'extensions #f) "extensions"))

(define (entitlement-like? claims)
  (and (hash? claims) (member (hash-ref claims 'type #f) '("entitlement" "trial")) #t))

(define (activation-claims? claims)
  (and (hash? claims) (equal? (hash-ref claims 'type #f) "activation")))

(define (validate-credential-claims claims)
  (define who 'validate-credential-claims)
  (expect who hash? "JSON object" claims "credential")
  (case (string->symbol (if (string? (hash-ref claims 'type #f))
                            (hash-ref claims 'type)
                            "invalid"))
    [(entitlement trial) (validate-common who claims)]
    [(activation) (validate-activation who claims)]
    [else (fail who "unsupported credential type" "type" (hash-ref claims 'type #f))])
  claims)

(define (parse-credential-payload payload)
  (unless (bytes? payload)
    (raise-argument-error 'parse-credential-payload "bytes?" payload))
  (define in (open-input-bytes payload))
  (define claims
    (with-handlers ([exn:fail? (lambda (e)
                                 (raise-arguments-error 'parse-credential-payload
                                                        "payload is not valid UTF-8 JSON"
                                                        "detail"
                                                        (exn-message e)))])
      (read-json in)))
  (unless (regexp-match? #px"^\\s*$" (port->string in))
    (fail 'parse-credential-payload "trailing data after JSON payload" "payload" payload))
  (validate-credential-claims claims))
