#lang racket/base

;; Issuer-side rights snapshots: typed constructors for the closed
;; entitlement schema, the lineage successor rule, and the one serialization
;; step the exact-byte rule allows. See docs/decisions/0001.

(require json
         "schema.rkt")

(provide subject
         grant
         constraints
         entitlement-payload
         successor-payload
         payload->bytes)

(define (subject #:type type
                 #:id id
                 #:display [display 'null])
  (hasheq 'type type 'id id 'display display))

(define (grant #:products [products '()]
               #:product-families [product-families '()]
               #:edition [edition 'null]
               #:feature-policy [feature-policy "explicit"]
               #:features [features '()]
               #:addons [addons '()]
               #:capabilities [capabilities (hasheq)])
  (hasheq 'scope (hasheq 'products products
                         'product_families product-families)
          'edition edition
          'feature_policy feature-policy
          'features features
          'addons addons
          'capabilities capabilities))

(define (constraints #:use-expires-at [use-expires-at 'null]
                     #:updates-through [updates-through 'null]
                     #:features-through [features-through 'null]
                     #:version-min [version-min 'null]
                     #:version-max [version-max 'null]
                     #:named-seats [named-seats 'null]
                     #:device-activations [device-activations 'null]
                     #:concurrent-seats [concurrent-seats 'null]
                     #:installation-id [installation-id 'null]
                     #:activation-required? [activation-required? #f])
  (hasheq 'use_expires_at use-expires-at
          'updates_through updates-through
          'features_through features-through
          'version_policy (hasheq 'min version-min 'max version-max)
          'limits (hasheq 'named_seats named-seats
                          'device_activations device-activations
                          'concurrent_seats concurrent-seats)
          'installation_id installation-id
          'activation_required activation-required?))

;; A complete, schema-validated entitlement-like payload. Validation runs
;; here so an invalid snapshot fails where it is built, not inside the signer.
(define (entitlement-payload #:type [type "entitlement"]
                             #:issuer issuer
                             #:credential-id credential-id
                             #:entitlement-id entitlement-id
                             #:revision [revision 0]
                             #:subject subject-value
                             #:channel [channel (if (equal? type "trial") "trial" "commercial")]
                             #:grants grants
                             #:constraints [constraints-value (constraints)]
                             #:issued-at issued-at
                             #:not-before [not-before 'null]
                             #:extensions [extensions (hasheq)])
  (validate-credential-claims
   (hasheq 'protocol "permit"
           'version 1
           'type type
           'credential_id credential-id
           'entitlement_id entitlement-id
           'revision revision
           'issuer issuer
           'issued_at issued-at
           'not_before not-before
           'subject subject-value
           'channel channel
           'grants grants
           'constraints constraints-value
           'extensions extensions)))

;; The next revision of an existing lineage. Identity fields are inherited
;; and cannot be replaced; everything a renewal, plan change, or withdrawal
;; may legitimately alter is a keyword that defaults to the previous value.
(define (successor-payload previous
                           #:credential-id credential-id
                           #:issued-at issued-at
                           #:subject [subject-value #f]
                           #:channel [channel #f]
                           #:grants [grants #f]
                           #:constraints [constraints-value #f]
                           #:not-before [not-before 'null]
                           #:extensions [extensions #f])
  (define claims (validate-credential-claims previous))
  (unless (entitlement-like? claims)
    (raise-argument-error 'successor-payload
                          "entitlement or trial claims"
                          previous))
  (entitlement-payload #:type (hash-ref claims 'type)
                       #:issuer (hash-ref claims 'issuer)
                       #:credential-id credential-id
                       #:entitlement-id (hash-ref claims 'entitlement_id)
                       #:revision (add1 (hash-ref claims 'revision))
                       #:subject (or subject-value (hash-ref claims 'subject))
                       #:channel (or channel (hash-ref claims 'channel))
                       #:grants (or grants (hash-ref claims 'grants))
                       #:constraints (or constraints-value (hash-ref claims 'constraints))
                       #:issued-at issued-at
                       #:not-before not-before
                       #:extensions (or extensions (hash-ref claims 'extensions))))

;; The one serialization. Callers sign and store these bytes; nothing may
;; re-serialize the jsexpr afterwards.
(define (payload->bytes jsexpr)
  (string->bytes/utf-8 (jsexpr->string jsexpr)))
