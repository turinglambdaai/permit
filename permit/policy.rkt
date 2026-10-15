#lang racket/base

(require racket/list
         racket/match
         racket/string
         "credential.rkt"
         "private/time.rkt"
         "schema.rkt")

(provide credential-usable?
         credential-status
         activation-valid?
         feature-entitled?
         edition-entitled?
         update-entitled?
         capability-value
         version-allowed?)

(define (claims-of who value)
  (unless (verified-credential? value)
    (raise-argument-error who "verified-credential?" value))
  (verified-credential-claims value))

(define (time-valid? claims at)
  (define issued-at (hash-ref claims 'issued_at))
  (define not-before (hash-ref claims 'not_before))
  (and (rfc3339<=? issued-at at) (or (eq? not-before 'null) (rfc3339<=? not-before at))))

(define (activation-valid? entitlement activation installation-id #:at [at (current-rfc3339)])
  (define entitlement-claims (claims-of 'activation-valid? entitlement))
  (define activation-claims (claims-of 'activation-valid? activation))
  (and (entitlement-like? entitlement-claims)
       (activation-claims? activation-claims)
       (time-valid? activation-claims at)
       (equal? (hash-ref activation-claims 'entitlement_id)
               (hash-ref entitlement-claims 'credential_id))
       (equal? (hash-ref activation-claims 'installation_id) installation-id)
       (<= (rfc3339->seconds at)
           (+ (rfc3339->seconds (hash-ref activation-claims 'valid_until))
              (hash-ref activation-claims 'offline_grace_seconds)))))

(define (credential-status credential
                           #:at [at (current-rfc3339)]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f])
  (define claims (claims-of 'credential-status credential))
  (unless (entitlement-like? claims)
    (raise-arguments-error 'credential-status
                           "expected an entitlement or trial credential"
                           "type"
                           (hash-ref claims 'type #f)))
  (define constraints (hash-ref claims 'constraints))
  (define reasons '())
  (define (reject! reason)
    (set! reasons (cons reason reasons)))
  (unless (rfc3339<=? (hash-ref claims 'issued_at) at)
    (reject! 'issued-in-future))
  (define not-before (hash-ref claims 'not_before))
  (when (and (not (eq? not-before 'null)) (not (rfc3339<=? not-before at)))
    (reject! 'not-active-yet))
  (define use-expires-at (hash-ref constraints 'use_expires_at))
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
  (hasheq 'usable? (null? reasons) 'reasons (reverse reasons)))

(define (credential-usable? credential
                            #:at [at (current-rfc3339)]
                            #:installation-id [installation-id #f]
                            #:activation [activation #f])
  (hash-ref
   (credential-status credential #:at at #:installation-id installation-id #:activation activation)
   'usable?))

(define (scope-matches? scope product product-family)
  (or (member product (hash-ref scope 'products))
      (and product-family (member product-family (hash-ref scope 'product_families)))))

(define (matching-grants credential product product-family)
  (filter (lambda (grant) (scope-matches? (hash-ref grant 'scope) product product-family))
          (hash-ref (claims-of 'matching-grants credential) 'grants)))

(define (split-version value)
  (define match
    (and (string? value)
         (regexp-match #px"^v?([0-9]+(?:\\.[0-9]+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$"
                       value)))
  (and match
       (list (map string->number (string-split (list-ref match 1) "."))
             (and (list-ref match 2) (string-split (list-ref match 2) ".")))))

(define (compare-list left right comparator equal?)
  (cond
    [(and (null? left) (null? right)) 0]
    [(null? left) -1]
    [(null? right) 1]
    [(equal? (car left) (car right)) (compare-list (cdr left) (cdr right) comparator equal?)]
    [(comparator (car left) (car right)) -1]
    [else 1]))

(define (compare-prerelease left right)
  (cond
    [(and (not left) (not right)) 0]
    [(not left) 1]
    [(not right) -1]
    [else
     (let loop ([left left]
                [right right])
       (cond
         [(and (null? left) (null? right)) 0]
         [(null? left) -1]
         [(null? right) 1]
         [else
          (define lnum (string->number (car left)))
          (define rnum (string->number (car right)))
          (define result
            (cond
              [(and lnum rnum)
               (cond
                 [(< lnum rnum) -1]
                 [(> lnum rnum) 1]
                 [else 0])]
              [lnum -1]
              [rnum 1]
              [(string<? (car left) (car right)) -1]
              [(string>? (car left) (car right)) 1]
              [else 0]))
          (if (zero? result)
              (loop (cdr left) (cdr right))
              result)]))]))

(define (version-compare left right)
  (define left* (split-version left))
  (define right* (split-version right))
  (unless left*
    (raise-argument-error 'version-allowed? "SemVer-compatible string" left))
  (unless right*
    (raise-argument-error 'version-allowed? "SemVer-compatible string" right))
  (define cores
    (compare-list (append (first left*) (make-list (- 4 (length (first left*))) 0))
                  (append (first right*) (make-list (- 4 (length (first right*))) 0))
                  <
                  =))
  (if (zero? cores)
      (compare-prerelease (second left*) (second right*))
      cores))

(define (version-allowed? credential version)
  (define policy
    (hash-ref (hash-ref (claims-of 'version-allowed? credential) 'constraints) 'version_policy))
  (define minimum (hash-ref policy 'min))
  (define maximum (hash-ref policy 'max))
  (and (or (eq? minimum 'null) (>= (version-compare version minimum) 0))
       (or (eq? maximum 'null) (<= (version-compare version maximum) 0))))

(define (base-policy-ok? credential at installation-id activation version)
  (and
   (credential-usable? credential #:at at #:installation-id installation-id #:activation activation)
   (or (not version) (version-allowed? credential version))))

(define (edition-entitled? credential
                           product
                           edition
                           #:at [at (current-rfc3339)]
                           #:product-family [product-family #f]
                           #:version [version #f]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f])
  (and (base-policy-ok? credential at installation-id activation version)
       (for/or ([grant (in-list (matching-grants credential product product-family))])
         (equal? (hash-ref grant 'edition) edition))
       #t))

(define (window-allows? credential constraint-name published-at)
  (define cutoff
    (hash-ref (hash-ref (claims-of 'window-allows? credential) 'constraints) constraint-name))
  (or (eq? cutoff 'null) (and published-at (rfc3339<=? published-at cutoff))))

(define (feature-entitled? credential
                           product
                           feature
                           #:published-at [published-at #f]
                           #:at [at (current-rfc3339)]
                           #:product-family [product-family #f]
                           #:version [version #f]
                           #:installation-id [installation-id #f]
                           #:activation [activation #f])
  (and (base-policy-ok? credential at installation-id activation version)
       (window-allows? credential 'features_through published-at)
       (for/or ([grant (in-list (matching-grants credential product product-family))])
         (member feature (hash-ref grant 'features)))
       #t))

(define (update-entitled? credential
                          product
                          published-at
                          #:at [at (current-rfc3339)]
                          #:product-family [product-family #f]
                          #:version [version #f]
                          #:installation-id [installation-id #f]
                          #:activation [activation #f])
  (and (base-policy-ok? credential at installation-id activation version)
       (pair? (matching-grants credential product product-family))
       (window-allows? credential 'updates_through published-at)))

(define (capability-value credential
                          product
                          capability
                          #:default [default #f]
                          #:at [at (current-rfc3339)]
                          #:product-family [product-family #f]
                          #:version [version #f]
                          #:installation-id [installation-id #f]
                          #:activation [activation #f])
  (if (base-policy-ok? credential at installation-id activation version)
      (for/fold ([result default])
                ([grant (in-list (matching-grants credential product product-family))])
        (hash-ref (hash-ref grant 'capabilities) capability result))
      default))
