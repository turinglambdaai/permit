#lang racket/base

(require racket/list
         "credential.rkt"
         "private/semver.rkt"
         "private/time.rkt"
         "schema.rkt")

(provide credential-usable?
         credential-status
         activation-valid?
         trial-extension-valid?
         feature-entitled?
         addon-entitled?
         edition-entitled?
         update-entitled?
         capability-value
         limit-value
         version-allowed?)

(define (claims-of who value)
  (unless (verified-credential? value)
    (raise-argument-error who "verified-credential?" value))
  (verified-credential-claims value))

(define (time-active? claims at)
  (define issued-at (hash-ref claims 'issued_at))
  (define not-before (hash-ref claims 'not_before))
  (and (rfc3339<=? issued-at at)
       (or (eq? not-before 'null) (rfc3339<=? not-before at))))

(define (activation-valid? entitlement activation installation-id #:at [at (current-rfc3339)])
  (define entitlement-claims (claims-of 'activation-valid? entitlement))
  (define activation-claims (claims-of 'activation-valid? activation))
  (and (entitlement-like? entitlement-claims)
       (activation-claims? activation-claims)
       (time-active? activation-claims at)
       (equal? (hash-ref activation-claims 'issuer)
               (hash-ref entitlement-claims 'issuer))
       (equal? (hash-ref activation-claims 'entitlement_id)
               (hash-ref entitlement-claims 'entitlement_id))
       (equal? (hash-ref activation-claims 'entitlement_credential_id)
               (hash-ref entitlement-claims 'credential_id))
       (= (hash-ref activation-claims 'entitlement_revision)
          (hash-ref entitlement-claims 'revision))
       (equal? (hash-ref activation-claims 'installation_id) installation-id)
       (<= (rfc3339->seconds at)
           (+ (rfc3339->seconds (hash-ref activation-claims 'valid_until))
              (hash-ref activation-claims 'offline_grace_seconds)))))

(define (trial-extension-valid? trial extension #:at [at (current-rfc3339)])
  (define trial-claims (claims-of 'trial-extension-valid? trial))
  (define extension-claims (claims-of 'trial-extension-valid? extension))
  (and (equal? (hash-ref trial-claims 'type #f) "trial")
       (trial-extension-claims? extension-claims)
       (time-active? extension-claims at)
       (equal? (hash-ref extension-claims 'issuer)
               (hash-ref trial-claims 'issuer))
       (equal? (hash-ref extension-claims 'trial_id)
               (hash-ref trial-claims 'entitlement_id))))

(define (later-time left right)
  (if (rfc3339<=? left right) right left))

(define (effective-use-expires-at credential trial-extensions at)
  (define claims (claims-of 'effective-use-expires-at credential))
  (define base (hash-ref (hash-ref claims 'constraints) 'use_expires_at))
  (cond
    [(not (equal? (hash-ref claims 'type) "trial"))
     (unless (null? trial-extensions)
       (raise-arguments-error 'credential-status
                              "trial extensions may only be supplied for trial credentials"
                              "type"
                              (hash-ref claims 'type)))
     base]
    [else
     (for/fold ([result base])
               ([extension (in-list trial-extensions)]
                #:when (trial-extension-valid? credential extension #:at at))
       (define extension-expiry
         (hash-ref (verified-credential-claims extension) 'use_expires_at))
       (later-time result extension-expiry))]))

(define (credential-status credential
                           #:at [at (current-rfc3339)]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f]
                           #:trial-extensions [trial-extensions '()])
  (define claims (claims-of 'credential-status credential))
  (unless (entitlement-like? claims)
    (raise-arguments-error 'credential-status
                           "expected an entitlement or trial credential"
                           "type"
                           (hash-ref claims 'type #f)))
  (unless (and (list? trial-extensions) (andmap verified-credential? trial-extensions))
    (raise-argument-error 'credential-status "(listof verified-credential?)" trial-extensions))
  (define constraints (hash-ref claims 'constraints))
  (define reasons '())
  (define (reject! reason)
    (set! reasons (cons reason reasons)))
  (unless (rfc3339<=? (hash-ref claims 'issued_at) at)
    (reject! 'issued-in-future))
  (define not-before (hash-ref claims 'not_before))
  (when (and (not (eq? not-before 'null)) (not (rfc3339<=? not-before at)))
    (reject! 'not-active-yet))
  (define use-expires-at (effective-use-expires-at credential trial-extensions at))
  (when (and (not (eq? use-expires-at 'null)) (not (rfc3339<=? at use-expires-at)))
    (reject! 'use-expired))
  (define bound-installation (hash-ref constraints 'installation_id))
  (when (and (not (eq? bound-installation 'null)) (not (equal? bound-installation installation-id)))
    (reject! 'installation-mismatch))
  (when (hash-ref constraints 'activation_required)
    (cond
      [(not activation) (reject! 'activation-required)]
      [(not installation-id) (reject! 'installation-id-required)]
      [(not (activation-valid? credential activation installation-id #:at at))
       (reject! 'activation-invalid)]))
  (hasheq 'usable?
          (null? reasons)
          'reasons
          (reverse reasons)
          'effective_use_expires_at
          use-expires-at))

(define (credential-usable? credential
                            #:at [at (current-rfc3339)]
                            #:installation-id [installation-id #f]
                            #:activation [activation #f]
                            #:trial-extensions [trial-extensions '()])
  (hash-ref
   (credential-status credential
                      #:at at
                      #:installation-id installation-id
                      #:activation activation
                      #:trial-extensions trial-extensions)
   'usable?))

(define (scope-matches? scope product product-family)
  (or (member product (hash-ref scope 'products))
      (and product-family (member product-family (hash-ref scope 'product_families)))))

(define (matching-grants credential product product-family)
  (filter (lambda (grant) (scope-matches? (hash-ref grant 'scope) product product-family))
          (hash-ref (claims-of 'matching-grants credential) 'grants)))

(define (version-allowed? credential version)
  (unless (semver? version)
    (raise-argument-error 'version-allowed? "SemVer 2.0 string" version))
  (define policy
    (hash-ref (hash-ref (claims-of 'version-allowed? credential) 'constraints) 'version_policy))
  (define minimum (hash-ref policy 'min))
  (define maximum (hash-ref policy 'max))
  (and (or (eq? minimum 'null) (>= (semver-compare version minimum) 0))
       (or (eq? maximum 'null) (<= (semver-compare version maximum) 0))))

(define (base-policy-ok? credential at installation-id activation version trial-extensions)
  (and
   (credential-usable? credential
                       #:at at
                       #:installation-id installation-id
                       #:activation activation
                       #:trial-extensions trial-extensions)
   (or (not version) (version-allowed? credential version))))

(define (edition-entitled? credential
                           product
                           edition
                           #:at [at (current-rfc3339)]
                           #:product-family [product-family #f]
                           #:version [version #f]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f]
                           #:trial-extensions [trial-extensions '()])
  (and (base-policy-ok? credential at installation-id activation version trial-extensions)
       (for/or ([grant (in-list (matching-grants credential product product-family))])
         (equal? (hash-ref grant 'edition) edition))
       #t))

(define (window-allows? credential constraint-name published-at)
  (when (and published-at (not (rfc3339-utc? published-at)))
    (raise-argument-error 'window-allows? "canonical RFC 3339 UTC timestamp or #f" published-at))
  (define cutoff
    (hash-ref (hash-ref (claims-of 'window-allows? credential) 'constraints) constraint-name))
  (or (eq? cutoff 'null)
      (and published-at (rfc3339<=? published-at cutoff))))

(define (feature-entitled? credential
                           product
                           feature
                           #:published-at [published-at #f]
                           #:at [at (current-rfc3339)]
                           #:product-family [product-family #f]
                           #:version [version #f]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f]
                           #:trial-extensions [trial-extensions '()])
  (and (base-policy-ok? credential at installation-id activation version trial-extensions)
       (window-allows? credential 'features_through published-at)
       (for/or ([grant (in-list (matching-grants credential product product-family))])
         (define features (hash-ref grant 'features))
         (or (member feature features)
             (member "*" features)))
       #t))

(define (addon-entitled? credential
                         product
                         addon
                         #:at [at (current-rfc3339)]
                         #:product-family [product-family #f]
                         #:version [version #f]
                         #:installation-id [installation-id #f]
                         #:activation [activation #f]
                         #:trial-extensions [trial-extensions '()])
  (and (base-policy-ok? credential at installation-id activation version trial-extensions)
       (for/or ([grant (in-list (matching-grants credential product product-family))])
         (member addon (hash-ref grant 'addons)))
       #t))

(define (update-entitled? credential
                          product
                          published-at
                          #:at [at (current-rfc3339)]
                          #:product-family [product-family #f]
                          #:version [version #f]
                          #:installation-id [installation-id #f]
                          #:activation [activation #f]
                          #:trial-extensions [trial-extensions '()])
  (unless (rfc3339-utc? published-at)
    (raise-argument-error 'update-entitled? "canonical RFC 3339 UTC timestamp" published-at))
  (and (base-policy-ok? credential at installation-id activation version trial-extensions)
       (pair? (matching-grants credential product product-family))
       (window-allows? credential 'updates_through published-at)))

(define (json-key who value)
  (cond
    [(symbol? value) value]
    [(and (string? value) (positive? (string-length value))) (string->symbol value)]
    [else (raise-argument-error who "(or/c symbol? non-empty-string?)" value)]))

(define (capability-value credential
                          product
                          capability
                          #:default [default #f]
                          #:at [at (current-rfc3339)]
                          #:product-family [product-family #f]
                          #:version [version #f]
                          #:installation-id [installation-id #f]
                          #:activation [activation #f]
                          #:trial-extensions [trial-extensions '()])
  (if (base-policy-ok? credential at installation-id activation version trial-extensions)
      (let* ([key (json-key 'capability-value capability)]
             [values
              (for/list ([grant (in-list (matching-grants credential product product-family))]
                         #:when (hash-has-key? (hash-ref grant 'capabilities) key))
                (hash-ref (hash-ref grant 'capabilities) key))])
        (cond
          [(null? values) default]
          [(andmap (lambda (value) (equal? value (car values))) (cdr values)) (car values)]
          [else
           (raise-arguments-error 'capability-value
                                  "conflicting values across matching grants"
                                  "product"
                                  product
                                  "capability"
                                  capability
                                  "values"
                                  values)]))
      default))

(define limit-names '(named_seats device_activations concurrent_seats))

(define (limit-value credential
                     limit
                     #:default [default #f]
                     #:at [at (current-rfc3339)]
                     #:installation-id [installation-id #f]
                     #:activation [activation #f]
                     #:trial-extensions [trial-extensions '()])
  (define key (json-key 'limit-value limit))
  (unless (memq key limit-names)
    (raise-arguments-error 'limit-value
                           "unknown Permit limit"
                           "limit"
                           limit
                           "allowed"
                           limit-names))
  (if (base-policy-ok? credential at installation-id activation #f trial-extensions)
      (let ([value
             (hash-ref (hash-ref (hash-ref (claims-of 'limit-value credential) 'constraints) 'limits)
                       key)])
        (if (eq? value 'null) default value))
      default))
