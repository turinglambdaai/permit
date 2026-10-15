#lang racket/base

(require json
         racket/list
         racket/port
         racket/string
         "private/semver.rkt"
         "private/time.rkt")

(provide parse-credential-payload
         validate-credential-claims
         entitlement-like?
         activation-claims?
         trial-extension-claims?)

(define entitlement-fields
  '(channel constraints credential_id entitlement_id extensions grants issued_at issuer
            not_before protocol revision subject type version))
(define activation-fields
  '(credential_id entitlement_credential_id entitlement_id entitlement_revision extensions
                  installation_id issued_at issuer lease_id not_before offline_grace_seconds
                  protocol type valid_until version))
(define trial-extension-fields
  '(credential_id trial_id extensions issued_at issuer not_before protocol type
                  use_expires_at version))
(define grant-fields '(addons capabilities edition features scope))
(define scope-fields '(product_families products))
(define constraints-fields
  '(activation_required features_through installation_id limits updates_through
                        use_expires_at version_policy))
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

(define (unique-string-list? value)
  (and (string-list? value)
       (= (length value) (length (remove-duplicates value string=?)))))

(define (nullable predicate)
  (lambda (value) (or (eq? value 'null) (predicate value))))

(define (exact-fields! who value expected label)
  (expect who hash? "JSON object" value label)
  (define actual (sort (hash-keys value) symbol<?))
  (define wanted (sort expected symbol<?))
  (unless (equal? actual wanted)
    (fail who (string-append "unexpected " label " fields") "expected" wanted "actual" actual)))

(define (validate-base who claims fields label)
  (exact-fields! who claims fields label)
  (unless (equal? (hash-ref claims 'protocol #f) "permit")
    (fail who "invalid protocol" "value" (hash-ref claims 'protocol #f)))
  (unless (equal? (hash-ref claims 'version #f) 1)
    (fail who "unsupported protocol version" "value" (hash-ref claims 'version #f)))
  (expect who non-empty-string? "non-empty string" (hash-ref claims 'credential_id #f) "credential_id")
  (expect who non-empty-string? "non-empty string" (hash-ref claims 'issuer #f) "issuer")
  (expect who rfc3339-utc? "canonical UTC timestamp" (hash-ref claims 'issued_at #f) "issued_at")
  (expect who
          (nullable rfc3339-utc?)
          "canonical UTC timestamp or null"
          (hash-ref claims 'not_before #f)
          "not_before")
  (expect who hash? "JSON object" (hash-ref claims 'extensions #f) "extensions"))

(define (validate-subject who value)
  (exact-fields! who value subject-fields "subject")
  (expect who non-empty-string? "non-empty string" (hash-ref value 'type #f) "subject.type")
  (expect who non-empty-string? "non-empty string" (hash-ref value 'id #f) "subject.id")
  (expect who (nullable string?) "string or null" (hash-ref value 'display #f) "subject.display"))

(define (validate-scope who value)
  (exact-fields! who value scope-fields "scope")
  (expect who
          unique-string-list?
          "list of unique non-empty strings"
          (hash-ref value 'products #f)
          "scope.products")
  (expect who
          unique-string-list?
          "list of unique non-empty strings"
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
  (expect who
          unique-string-list?
          "list of unique non-empty strings"
          (hash-ref value 'features #f)
          "grant.features")
  (expect who
          unique-string-list?
          "list of unique non-empty strings"
          (hash-ref value 'addons #f)
          "grant.addons")
  (define capabilities (hash-ref value 'capabilities #f))
  (expect who hash? "JSON object" capabilities "grant.capabilities")
  (for ([(name value) (in-hash capabilities)])
    (expect who symbol? "JSON object key" name "capability name")
    (expect who scalar-capability? "string, boolean, or number" value "capability value")))

(define (validate-version-policy who value)
  (exact-fields! who value version-policy-fields "constraints.version_policy")
  (for ([name (in-list version-policy-fields)])
    (expect who
            (nullable semver?)
            "SemVer 2.0 string or null"
            (hash-ref value name #f)
            (format "constraints.version_policy.~a" name)))
  (define minimum (hash-ref value 'min))
  (define maximum (hash-ref value 'max))
  (when (and (not (eq? minimum 'null))
             (not (eq? maximum 'null))
             (not (semver<=? minimum maximum)))
    (fail who
          "version policy minimum must not exceed maximum"
          "min"
          minimum
          "max"
          maximum)))

(define (validate-constraints who value credential-type)
  (exact-fields! who value constraints-fields "constraints")
  (for ([name (in-list '(use_expires_at updates_through features_through))])
    (expect who
            (nullable rfc3339-utc?)
            "canonical UTC timestamp or null"
            (hash-ref value name #f)
            (format "constraints.~a" name)))
  (when (and (equal? credential-type "trial")
             (eq? (hash-ref value 'use_expires_at) 'null))
    (fail who "trial must have a finite use_expires_at" "use_expires_at" 'null))
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
  (validate-version-policy who (hash-ref value 'version_policy #f)))

(define (validate-entitlement-like who claims)
  (validate-base who claims entitlement-fields "credential")
  (define type (hash-ref claims 'type #f))
  (unless (member type '("entitlement" "trial"))
    (fail who "unsupported entitlement-like type" "type" type))
  (expect who
          non-empty-string?
          "non-empty string"
          (hash-ref claims 'entitlement_id #f)
          "entitlement_id")
  (expect who
          exact-nonnegative-integer?
          "non-negative integer"
          (hash-ref claims 'revision #f)
          "revision")
  (validate-subject who (hash-ref claims 'subject #f))
  (expect who non-empty-string? "non-empty string" (hash-ref claims 'channel #f) "channel")
  (define grants (hash-ref claims 'grants #f))
  (expect who list? "list" grants "grants")
  (when (null? grants)
    (fail who "credential must contain at least one grant" "grants" grants))
  (for ([grant (in-list grants)])
    (validate-grant who grant))
  (validate-constraints who (hash-ref claims 'constraints #f) type))

(define (validate-activation who claims)
  (validate-base who claims activation-fields "activation credential")
  (unless (equal? (hash-ref claims 'type #f) "activation")
    (fail who "invalid activation type" "type" (hash-ref claims 'type #f)))
  (for ([name (in-list '(entitlement_credential_id entitlement_id installation_id lease_id))])
    (expect who non-empty-string? "non-empty string" (hash-ref claims name #f) (symbol->string name)))
  (expect who
          exact-nonnegative-integer?
          "non-negative integer"
          (hash-ref claims 'entitlement_revision #f)
          "entitlement_revision")
  (expect who
          rfc3339-utc?
          "canonical UTC timestamp"
          (hash-ref claims 'valid_until #f)
          "valid_until")
  (unless (rfc3339<=? (hash-ref claims 'issued_at) (hash-ref claims 'valid_until))
    (fail who
          "activation valid_until must not precede issued_at"
          "issued_at"
          (hash-ref claims 'issued_at)
          "valid_until"
          (hash-ref claims 'valid_until)))
  (expect who
          exact-nonnegative-integer?
          "non-negative integer"
          (hash-ref claims 'offline_grace_seconds #f)
          "offline_grace_seconds"))

(define (validate-trial-extension who claims)
  (validate-base who claims trial-extension-fields "trial-extension credential")
  (unless (equal? (hash-ref claims 'type #f) "trial-extension")
    (fail who "invalid trial-extension type" "type" (hash-ref claims 'type #f)))
  (expect who
          non-empty-string?
          "non-empty string"
          (hash-ref claims 'trial_id #f)
          "trial_id")
  (expect who
          rfc3339-utc?
          "canonical UTC timestamp"
          (hash-ref claims 'use_expires_at #f)
          "use_expires_at")
  (unless (rfc3339<=? (hash-ref claims 'issued_at) (hash-ref claims 'use_expires_at))
    (fail who
          "trial extension must not expire before it is issued"
          "issued_at"
          (hash-ref claims 'issued_at)
          "use_expires_at"
          (hash-ref claims 'use_expires_at))))

(define (entitlement-like? claims)
  (and (hash? claims) (member (hash-ref claims 'type #f) '("entitlement" "trial")) #t))

(define (activation-claims? claims)
  (and (hash? claims) (equal? (hash-ref claims 'type #f) "activation")))

(define (trial-extension-claims? claims)
  (and (hash? claims) (equal? (hash-ref claims 'type #f) "trial-extension")))

(define (validate-credential-claims claims)
  (define who 'validate-credential-claims)
  (expect who hash? "JSON object" claims "credential")
  (define type (hash-ref claims 'type #f))
  (cond
    [(member type '("entitlement" "trial")) (validate-entitlement-like who claims)]
    [(equal? type "activation") (validate-activation who claims)]
    [(equal? type "trial-extension") (validate-trial-extension who claims)]
    [else (fail who "unsupported credential type" "type" type)])
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
