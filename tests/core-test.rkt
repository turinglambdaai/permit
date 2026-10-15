#lang racket/base

(require crypto
         (only-in crypto/libcrypto libcrypto-factory)
         json
         rackunit
         racket/file
         racket/port
         "../permit/main.rkt")

(define (hex->bytes value)
  (define output (make-bytes (/ (string-length value) 2)))
  (for ([index (in-range (bytes-length output))])
    (bytes-set! output
                index
                (string->number (substring value (* index 2) (+ (* index 2) 2)) 16)))
  output)

;; RFC 8032 test vector 1.
(define seed (hex->bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
(define public-raw (hex->bytes "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
(define rfc-signature
  (hex->bytes
   (string-append "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")))

(define private-key
  (datum->pk-key (list 'eddsa 'private 'ed25519 public-raw seed)
                 'rkt-private
                 (list libcrypto-factory)))
(define public-key (pk-key->public-only-key private-key))

(check-equal? (ed25519-sign private-key #"") rfc-signature)
(check-true (ed25519-verify public-key #"" rfc-signature))
(check-false (ed25519-verify public-key #"changed" rfc-signature))

(define (constraints #:use [use 'null]
                     #:updates [updates 'null]
                     #:features [features 'null]
                     #:installation [installation 'null]
                     #:activation? [activation? #f]
                     #:minimum [minimum 'null]
                     #:maximum [maximum 'null])
  (hasheq 'use_expires_at
          use
          'updates_through
          updates
          'features_through
          features
          'version_policy
          (hasheq 'min minimum 'max maximum)
          'limits
          (hasheq 'named_seats 5 'device_activations 10 'concurrent_seats 2)
          'installation_id
          installation
          'activation_required
          activation?))

(define default-grant
  (hasheq 'scope
          (hasheq 'products '("gptp-studio" "benchpilot")
                  'product_families '("automotive-tools"))
          'edition
          "team"
          'feature_policy
          "explicit"
          'features
          '("pcap-export" "engine-control")
          'addons
          '("report-pack")
          'capabilities
          (hasheq 'team-members 5 'devices 10)))

(define published-through-grant
  (hasheq 'scope
          (hasheq 'products '("gptp-studio") 'product_families '())
          'edition
          "pro"
          'feature_policy
          "published-through"
          'features
          '()
          'addons
          '()
          'capabilities
          (hasheq)))

(define (entitlement credential-id
                     constraints-value
                     #:entitlement-id [entitlement-id (string-append "right_" credential-id)]
                     #:revision [revision 0]
                     #:type [type "entitlement"]
                     #:issued-at [issued-at "2026-01-01T00:00:00Z"]
                     #:grants [grants (list default-grant)])
  (hasheq 'protocol
          "permit"
          'version
          1
          'type
          type
          'credential_id
          credential-id
          'entitlement_id
          entitlement-id
          'revision
          revision
          'issuer
          "example.test"
          'issued_at
          issued-at
          'not_before
          'null
          'subject
          (hasheq 'type "organization" 'id "org_example" 'display "Example Team")
          'channel
          (if (equal? type "trial") "trial" "commercial")
          'grants
          grants
          'constraints
          constraints-value
          'extensions
          (hasheq)))

(define (activation entitlement-claims
                    installation-id
                    #:valid-until [valid-until "2026-12-31T23:59:59Z"]
                    #:grace [grace 0])
  (hasheq 'protocol
          "permit"
          'version
          1
          'type
          "activation"
          'credential_id
          (string-append "act_" (hash-ref entitlement-claims 'credential_id))
          'entitlement_id
          (hash-ref entitlement-claims 'entitlement_id)
          'entitlement_revision
          (hash-ref entitlement-claims 'revision)
          'entitlement_credential_id
          (hash-ref entitlement-claims 'credential_id)
          'issuer
          "example.test"
          'issued_at
          "2026-01-01T00:00:00Z"
          'not_before
          'null
          'lease_id
          (string-append "lease_" (hash-ref entitlement-claims 'credential_id))
          'installation_id
          installation-id
          'valid_until
          valid-until
          'offline_grace_seconds
          grace
          'extensions
          (hasheq)))

(define (trial-extension credential-id entitlement-id use-expires-at
                         #:issued-at [issued-at "2026-06-10T00:00:00Z"])
  (hasheq 'protocol
          "permit"
          'version
          1
          'type
          "trial-extension"
          'credential_id
          credential-id
          'trial_id
          entitlement-id
          'issuer
          "example.test"
          'issued_at
          issued-at
          'not_before
          'null
          'use_expires_at
          use-expires-at
          'extensions
          (hasheq)))

(define (json-bytes value)
  (call-with-output-bytes (lambda (out) (write-json value out))))

(define (key-entry #:status [status "active"]
                   #:not-before [not-before 'null]
                   #:not-after [not-after 'null]
                   #:purposes [purposes '("entitlement" "trial" "trial-extension" "activation")])
  (hasheq 'algorithm
          "Ed25519"
          'public_key
          (public-key->base64 public-key)
          'status
          status
          'purposes
          purposes
          'not_before
          not-before
          'not_after
          not-after))

(define (store-value-with key)
  (hasheq 'protocol
          "permit-trust-store"
          'version
          1
          'issuer
          "example.test"
          'keys
          (hasheq 'test-2026 key)))

(define store-value (store-value-with (key-entry)))
(define store (jsexpr->trust-store store-value))

(define (issue value [target-store store])
  (define payload (json-bytes value))
  (verify-credential (make-signed-envelope "test-2026" payload private-key) target-store))

;; Exact payload bytes, not JSON semantics, are signed.
(define exact-payload (json-bytes (entitlement "cred_exact" (constraints))))
(define exact-envelope (make-signed-envelope "test-2026" exact-payload private-key))
(check-equal? (permit-envelope-payload exact-envelope) exact-payload)
(check-true (verify-envelope-signature exact-envelope public-key))
(check-false
 (verify-envelope-signature
  (struct-copy permit-envelope exact-envelope [payload (bytes-append exact-payload #" ")])
  public-key))

;; The outer wrapper must contain exactly one JSON value.
(define envelope-bytes
  (call-with-output-bytes (lambda (out) (write-envelope exact-envelope out))))
(check-exn exn:fail?
           (lambda ()
             (read-envelope (open-input-bytes (bytes-append envelope-bytes #"{}")))))

;; Signed/trusted JSON inputs reject duplicate object keys before semantic use.
(check-exn #rx"duplicate JSON object member"
           (lambda ()
             (parse-credential-payload
              #"{\"protocol\":\"permit\",\"protocol\":\"permit\"}")))
(check-exn #rx"duplicate JSON object member"
           (lambda ()
             (read-envelope
              (open-input-string
               "{\"permit_version\":1,\"permit_version\":1,\"algorithm\":\"Ed25519\",\"key_id\":\"x\",\"payload\":\"\",\"signature\":\"\"}"))))

;; Strict time and schema validation.
(check-exn #rx"invalid issued_at"
           (lambda ()
             (validate-credential-claims
              (hash-set (entitlement "cred_bad_date" (constraints))
                        'issued_at
                        "2026-02-31T00:00:00Z"))))
(check-exn #rx"trial must have a finite"
           (lambda ()
             (validate-credential-claims
              (entitlement "cred_infinite_trial" (constraints)
                           #:type "trial"))))
(check-exn #rx"unexpected credential fields"
           (lambda ()
             (validate-credential-claims
              (hash-set (entitlement "cred_typo" (constraints)) 'expires_at 'null))))

;; Perpetual purchase.
(define perpetual (issue (entitlement "cred_perpetual" (constraints))))
(check-true (credential-usable? perpetual #:at "2035-01-01T00:00:00Z"))
(check-true
 (feature-entitled? perpetual
                    "gptp-studio"
                    "pcap-export"
                    #:at "2035-01-01T00:00:00Z"))
(check-true
 (addon-entitled? perpetual
                  "gptp-studio"
                  "report-pack"
                  #:at "2035-01-01T00:00:00Z"))
(check-true
 (update-entitled? perpetual
                   "gptp-studio"
                   "2035-01-01T00:00:00Z"
                   #:at "2035-01-01T00:00:00Z"))
(check-equal? (capability-value perpetual "benchpilot" 'team-members) 5)
(check-equal? (limit-value perpetual 'named_seats) 5)
(check-true
 (edition-entitled? perpetual "unknown-product" "team" #:product-family "automotive-tools"))

;; Perpetual use + maintenance cutoff.
(define perpetual-maintenance
  (issue
   (entitlement "cred_maintenance"
                (constraints #:updates "2027-10-15T23:59:59Z"))))
(check-true (credential-usable? perpetual-maintenance #:at "2030-01-01T00:00:00Z"))
(check-true
 (update-entitled? perpetual-maintenance
                   "gptp-studio"
                   "2027-10-15T23:59:59Z"
                   #:at "2030-01-01T00:00:00Z"))
(check-false
 (update-entitled? perpetual-maintenance
                   "gptp-studio"
                   "2027-10-16T00:00:00Z"
                   #:at "2030-01-01T00:00:00Z"))

;; Perpetual use + feature publication cutoff.
(define perpetual-feature-window
  (issue
   (entitlement "cred_feature_window"
                (constraints #:features "2027-10-15T23:59:59Z")
                #:grants (list published-through-grant))))
(check-true
 (feature-entitled? perpetual-feature-window
                    "gptp-studio"
                    "pcap-export"
                    #:published-at "2027-10-15T23:59:59Z"
                    #:at "2030-01-01T00:00:00Z"))
(check-false
 (feature-entitled? perpetual-feature-window
                    "gptp-studio"
                    "pcap-export"
                    #:published-at "2027-10-16T00:00:00Z"
                    #:at "2030-01-01T00:00:00Z"))

(check-true
 (feature-entitled? perpetual
                    "gptp-studio"
                    "pcap-export"
                    #:published-at "2099-01-01T00:00:00Z"
                    #:at "2030-01-01T00:00:00Z"))


(define future-feature-window
  (issue
   (entitlement "cred_future_feature_window"
                (constraints #:features "2027-10-15T23:59:59Z")
                #:grants (list published-through-grant))))
(check-true
 (feature-entitled? future-feature-window
                    "gptp-studio"
                    "agent-mode-added-later"
                    #:published-at "2027-09-01T00:00:00Z"
                    #:at "2030-01-01T00:00:00Z"))
(check-false
 (feature-entitled? future-feature-window
                    "gptp-studio"
                    "agent-mode-added-later"
                    #:published-at "2027-11-01T00:00:00Z"
                    #:at "2030-01-01T00:00:00Z"))
(check-false
 (feature-entitled? future-feature-window
                    "gptp-studio"
                    "agent-mode-added-later"
                    #:at "2030-01-01T00:00:00Z"))

;; True subscription.
(define subscription
  (issue
   (entitlement "cred_subscription"
                (constraints #:use "2026-06-30T23:59:59Z"))))
(check-true (credential-usable? subscription #:at "2026-06-30T23:59:59Z"))
(check-false (credential-usable? subscription #:at "2026-07-01T00:00:00Z"))

;; Signed trial extension uses an absolute expiry and is replay-safe.
(define trial-claims
  (entitlement "cred_trial"
               (constraints #:use "2026-06-14T23:59:59Z")
               #:entitlement-id "trial_support_01"
               #:type "trial"))
(define trial (issue trial-claims))
(define extension
  (issue
   (trial-extension "ext_trial_01"
                    "trial_support_01"
                    "2026-06-21T23:59:59Z")))
(define wrong-extension
  (issue
   (trial-extension "ext_other"
                    "some_other_trial"
                    "2026-07-01T23:59:59Z")))
(check-false (credential-usable? trial #:at "2026-06-20T00:00:00Z"))
(check-true
 (credential-usable? trial
                     #:at "2026-06-20T00:00:00Z"
                     #:trial-extensions (list extension)))
(check-true
 (credential-usable? trial
                     #:at "2026-06-20T00:00:00Z"
                     #:trial-extensions (list extension extension)))
(check-false
 (credential-usable? trial
                     #:at "2026-06-22T00:00:00Z"
                     #:trial-extensions (list extension wrong-extension)))

;; Optional installation binding.
(define installed
  (issue
   (entitlement "cred_installed"
                (constraints #:installation "ins_A"))))
(check-true (credential-usable? installed #:installation-id "ins_A"))
(check-false (credential-usable? installed #:installation-id "ins_B"))

;; Managed entitlement: activation is bound to the exact entitlement snapshot.
(define managed-claims
  (entitlement "cred_managed_r0"
               (constraints #:activation? #t)
               #:entitlement-id "ent_managed"
               #:revision 0))
(define managed (issue managed-claims))
(define good-activation (issue (activation managed-claims "ins_A")))
(define other-activation (issue (activation managed-claims "ins_B")))
(check-false (credential-usable? managed #:installation-id "ins_A"))
(check-true
 (credential-usable? managed
                     #:at "2026-06-01T00:00:00Z"
                     #:installation-id "ins_A"
                     #:activation good-activation))
(check-false
 (credential-usable? managed
                     #:at "2026-06-01T00:00:00Z"
                     #:installation-id "ins_A"
                     #:activation other-activation))

(define managed-r1-claims
  (entitlement "cred_managed_r1"
               (constraints #:activation? #t)
               #:entitlement-id "ent_managed"
               #:revision 1))
(define managed-r1 (issue managed-r1-claims))
(check-false
 (credential-usable? managed-r1
                     #:at "2026-06-01T00:00:00Z"
                     #:installation-id "ins_A"
                     #:activation good-activation))

(define grace-activation
  (issue
   (activation managed-claims
               "ins_A"
               #:valid-until "2026-05-31T23:59:00Z"
               #:grace 120)))
(check-true
 (activation-valid? managed grace-activation "ins_A" #:at "2026-06-01T00:01:00Z"))
(check-false
 (activation-valid? managed grace-activation "ins_A" #:at "2026-06-01T00:01:01Z"))

;; Lineage selection is deterministic but is explicitly not revocation.
(check-equal?
 (verified-credential-id (select-latest-entitlement (list managed managed-r1)))
 "cred_managed_r1")
(define conflicting-r1
  (issue
   (entitlement "cred_managed_r1_conflict"
                (constraints #:activation? #t #:updates "2028-01-01T00:00:00Z")
                #:entitlement-id "ent_managed"
                #:revision 1)))
(check-exn #rx"conflicting credentials"
           (lambda ()
             (select-latest-entitlement (list managed-r1 conflicting-r1))))

;; SemVer 2.0 bounds are strict and portable.
(define bounded
  (issue
   (entitlement "cred_bounded"
                (constraints #:minimum "2.0.0" #:maximum "3.0.0"))))
(check-true (version-allowed? bounded "2.5.0"))
(check-true (version-allowed? bounded "3.0.0"))
(check-false
 (feature-entitled? bounded
                    "gptp-studio"
                    "pcap-export"
                    #:at "2026-06-01T00:00:00Z"))
(check-true
 (feature-entitled? bounded
                    "gptp-studio"
                    "pcap-export"
                    #:version "2.5.0"
                    #:at "2026-06-01T00:00:00Z"))
(check-false (version-allowed? bounded "3.0.1"))
(check-false (version-allowed? bounded "2.0.0-alpha"))
(check-exn exn:fail? (lambda () (version-allowed? bounded "2.0")))
(check-exn exn:fail? (lambda () (version-allowed? bounded "v2.0.0")))
(check-exn exn:fail?
           (lambda ()
             (validate-credential-claims
              (entitlement "cred_bad_range"
                           (constraints #:minimum "3.0.0" #:maximum "2.0.0")))))

;; Matching grants may not silently disagree on a scalar capability.
(define conflicting-grants
  (list default-grant
        (hasheq 'scope
                (hasheq 'products '("gptp-studio") 'product_families '())
                'edition "team"
                'feature_policy "explicit"
                'features '()
                'addons '()
                'capabilities (hasheq 'team-members 99))))
(define conflict-capability
  (issue
   (entitlement "cred_cap_conflict"
                (constraints)
                #:grants conflicting-grants)))
(check-exn #rx"conflicting values"
           (lambda ()
             (capability-value conflict-capability "gptp-studio" 'team-members)))

;; Key validity windows apply to authenticated issued_at, not wall-clock
;; verification time. This preserves perpetual credentials after rotation.
(define retired-window-store
  (jsexpr->trust-store
   (store-value-with
    (key-entry #:status "retired"
               #:not-before "2026-01-01T00:00:00Z"
               #:not-after "2026-12-31T23:59:59Z"))))
(define old-entitlement
  (issue
   (entitlement "cred_old"
                (constraints)
                #:issued-at "2026-06-01T00:00:00Z")
   retired-window-store))
(check-true (credential-usable? old-entitlement #:at "2035-01-01T00:00:00Z"))
(check-exn #rx"issuance window"
           (lambda ()
             (issue
              (entitlement "cred_too_new"
                           (constraints)
                           #:issued-at "2027-01-01T00:00:00Z")
              retired-window-store)))

;; Key purpose separation prevents an online activation signer from minting
;; durable entitlements even when the signature is otherwise valid.
(define activation-only-store
  (jsexpr->trust-store
   (store-value-with (key-entry #:purposes '("activation")))))
(check-exn #rx"not authorized for credential type"
           (lambda ()
             (verify-credential exact-envelope activation-only-store)))

;; Revocation is the explicit mechanism that invalidates all credentials from a
;; compromised key.
(define revoked-store
  (jsexpr->trust-store
   (store-value-with (key-entry #:status "revoked"))))
(check-exn #rx"revoked"
           (lambda ()
             (verify-credential exact-envelope revoked-store)))

;; A future issued_at is authentic but not currently usable. Authentication and
;; policy evaluation are intentionally separate stages.
(define future
  (issue
   (entitlement "cred_future"
                (constraints)
                #:issued-at "2030-01-01T00:00:00Z")))
(check-false (credential-usable? future #:at "2029-12-31T23:59:59Z"))
(check-true (credential-usable? future #:at "2030-01-01T00:00:00Z"))


;; Add-on-only grants do not need to invent an edition.
(define addon-only-grant
  (hasheq 'scope
          (hasheq 'products '("gptp-studio") 'product_families '())
          'edition
          'null
          'feature_policy
          "explicit"
          'features
          '()
          'addons
          '("hardware-pack")
          'capabilities
          (hasheq)))
(define addon-only
  (issue
   (entitlement "cred_addon_only"
                (constraints)
                #:grants (list addon-only-grant))))
(check-true (addon-entitled? addon-only "gptp-studio" "hardware-pack"))
(check-false (edition-entitled? addon-only "gptp-studio" "pro"))

;; Trust metadata may not alias one public key under several key ids, because
;; key_id is an outer selector rather than signed business data.
(define duplicate-key-entry (key-entry))
(check-exn
 #rx"same public key"
 (lambda ()
   (jsexpr->trust-store
    (hasheq 'protocol
            "permit-trust-store"
            'version
            1
            'issuer
            "example.test"
            'keys
            (hasheq 'key-a duplicate-key-entry
                    'key-b duplicate-key-entry)))))

(check-exn
 #rx"next key requires"
 (lambda ()
   (jsexpr->trust-store (store-value-with (key-entry #:status "next")))))

(check-exn
 #rx"retired key requires"
 (lambda ()
   (jsexpr->trust-store (store-value-with (key-entry #:status "retired")))))

;; Capability numbers must be finite JSON-style numbers.
(check-exn
 #rx"invalid capability value"
 (lambda ()
   (validate-credential-claims
    (entitlement
     "cred_infinite_capability"
     (constraints)
     #:grants
     (list
      (hasheq 'scope
              (hasheq 'products '("gptp-studio") 'product_families '())
              'edition
              'null
              'feature_policy
              "explicit"
              'features
              '()
              'addons
              '()
              'capabilities
              (hasheq 'bad +inf.0)))))))


;; Management artifacts and lineage selection are issuer-scoped. Products may
;; trust several independent issuers without allowing their credentials to mix.
(define other-store
  (jsexpr->trust-store
   (hasheq 'protocol
           "permit-trust-store"
           'version
           1
           'issuer
           "other.test"
           'keys
           (hasheq 'test-2026 (key-entry)))))

(define (issue-other value)
  (define payload (json-bytes (hash-set value 'issuer "other.test")))
  (verify-credential
   (make-signed-envelope "test-2026" payload private-key)
   other-store))

(define foreign-activation
  (issue-other (activation managed-claims "ins_A")))
(check-false
 (activation-valid? managed
                    foreign-activation
                    "ins_A"
                    #:at "2026-06-01T00:00:00Z"))

(define foreign-extension
  (issue-other
   (trial-extension "ext_foreign"
                    "trial_support_01"
                    "2026-06-30T23:59:59Z")))
(check-false
 (trial-extension-valid? trial
                         foreign-extension
                         #:at "2026-06-20T00:00:00Z"))

(define foreign-lineage
  (issue-other
   (entitlement "cred_foreign_lineage"
                (constraints)
                #:entitlement-id "ent_managed"
                #:revision 2)))
(check-exn #rx"different entitlement lineages"
           (lambda ()
             (select-latest-entitlement (list managed-r1 foreign-lineage))))
