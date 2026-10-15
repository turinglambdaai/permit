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
    (bytes-set! output index (string->number (substring value (* index 2) (+ (* index 2) 2)) 16)))
  output)

(define seed (hex->bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
(define public-raw (hex->bytes "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
(define rfc-signature
  (hex->bytes (string-append "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
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
          (hasheq 'products '("gptp-studio" "benchpilot") 'product_families '("automotive-tools"))
          'edition
          "team"
          'features
          '("pcap-export" "engine-control")
          'addons
          '("report-pack")
          'capabilities
          (hasheq 'team-members 5 'devices 10)))

(define (entitlement id constraints-value #:type [type "entitlement"])
  (hasheq 'protocol
          "permit"
          'version
          1
          'type
          type
          'credential_id
          id
          'issuer
          "example.test"
          'issued_at
          "2026-01-01T00:00:00Z"
          'not_before
          'null
          'subject
          (hasheq 'type "organization" 'id "org_example" 'display "Example Team")
          'channel
          (if (equal? type "trial") "trial" "commercial")
          'grants
          (list default-grant)
          'constraints
          constraints-value
          'extensions
          (hasheq)))

(check-exn #rx"invalid issued_at"
           (lambda ()
             (validate-credential-claims (hash-set (entitlement "ent_bad_date" (constraints))
                                                   'issued_at
                                                   "2026-02-31T00:00:00Z"))))

(define (activation entitlement-id
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
          (string-append "act_" entitlement-id)
          'entitlement_id
          entitlement-id
          'issuer
          "example.test"
          'issued_at
          "2026-01-01T00:00:00Z"
          'not_before
          'null
          'lease_id
          (string-append "lease_" entitlement-id)
          'installation_id
          installation-id
          'valid_until
          valid-until
          'offline_grace_seconds
          grace
          'extensions
          (hasheq)))

(define (json-bytes value)
  (call-with-output-bytes (lambda (out) (write-json value out))))

(define store-value
  (hasheq 'protocol
          "permit-trust-store"
          'version
          1
          'issuer
          "example.test"
          'keys
          (hasheq 'test-2026
                  (hasheq 'algorithm
                          "Ed25519"
                          'public_key
                          (public-key->base64 public-key)
                          'status
                          "active"
                          'not_before
                          'null
                          'not_after
                          'null))))
(define store (jsexpr->trust-store store-value))

(define (issue value [key-id "test-2026"])
  (define payload (json-bytes value))
  (verify-credential (make-signed-envelope key-id payload private-key)
                     store
                     #:at "2026-06-01T00:00:00Z"))

(define exact-payload (json-bytes (entitlement "ent_exact" (constraints))))
(define exact-envelope (make-signed-envelope "test-2026" exact-payload private-key))
(check-equal? (permit-envelope-payload exact-envelope) exact-payload)
(check-true (verify-envelope-signature exact-envelope public-key))
(check-false (verify-envelope-signature
              (struct-copy permit-envelope exact-envelope [payload (bytes-append exact-payload #" ")])
              public-key))

(define perpetual (issue (entitlement "ent_perpetual" (constraints))))
(check-true (credential-usable? perpetual #:at "2035-01-01T00:00:00Z"))
(check-true (feature-entitled? perpetual "gptp-studio" "pcap-export" #:at "2035-01-01T00:00:00Z"))
(check-true
 (update-entitled? perpetual "gptp-studio" "2035-01-01T00:00:00Z" #:at "2035-01-01T00:00:00Z"))
(check-equal? (capability-value perpetual "benchpilot" 'team-members) 5)
(check-true
 (edition-entitled? perpetual "unknown-product" "team" #:product-family "automotive-tools"))

;; Perpetual use with updates published only inside the maintenance window.
(define perpetual-maintenance
  (issue (entitlement "ent_perpetual_maintenance" (constraints #:updates "2027-10-15T23:59:59Z"))))
(check-true (credential-usable? perpetual-maintenance #:at "2030-01-01T00:00:00Z"))
(check-true (update-entitled? perpetual-maintenance
                              "gptp-studio"
                              "2027-10-15T23:59:59Z"
                              #:at "2030-01-01T00:00:00Z"))
(check-false (update-entitled? perpetual-maintenance
                               "gptp-studio"
                               "2027-10-16T00:00:00Z"
                               #:at "2030-01-01T00:00:00Z"))

;; Perpetual use while newly published features stop at a distinct cutoff.
(define perpetual-feature-window
  (issue (entitlement "ent_perpetual_feature_window"
                      (constraints #:features "2027-10-15T23:59:59Z"))))
(check-true (update-entitled? perpetual-feature-window
                              "gptp-studio"
                              "2030-01-01T00:00:00Z"
                              #:at "2030-01-01T00:00:00Z"))
(check-true (feature-entitled? perpetual-feature-window
                               "gptp-studio"
                               "pcap-export"
                               #:published-at "2027-10-15T23:59:59Z"
                               #:at "2030-01-01T00:00:00Z"))
(check-false (feature-entitled? perpetual-feature-window
                                "gptp-studio"
                                "pcap-export"
                                #:published-at "2027-10-16T00:00:00Z"
                                #:at "2030-01-01T00:00:00Z"))

(define subscription
  (issue (entitlement "ent_subscription" (constraints #:use "2026-06-30T23:59:59Z"))))
(check-true (credential-usable? subscription #:at "2026-06-30T23:59:59Z"))
(check-false (credential-usable? subscription #:at "2026-07-01T00:00:00Z"))

(define trial
  (issue (entitlement "trial_01" (constraints #:use "2026-06-14T23:59:59Z") #:type "trial")))
(check-equal? (verified-credential-type trial) "trial")
(check-true (credential-usable? trial #:at "2026-06-14T23:59:59Z"))
(check-false (credential-usable? trial #:at "2026-06-15T00:00:00Z"))

(define installed (issue (entitlement "ent_installed" (constraints #:installation "ins_A"))))
(check-true (credential-usable? installed #:installation-id "ins_A"))
(check-false (credential-usable? installed #:installation-id "ins_B"))

(define managed (issue (entitlement "ent_managed" (constraints #:activation? #t))))
(define good-activation (issue (activation "ent_managed" "ins_A")))
(define other-activation (issue (activation "ent_managed" "ins_B")))
(check-false (credential-usable? managed #:installation-id "ins_A"))
(check-true (credential-usable? managed
                                #:at "2026-06-01T00:00:00Z"
                                #:installation-id "ins_A"
                                #:activation good-activation))
(check-false (credential-usable? managed
                                 #:at "2026-06-01T00:00:00Z"
                                 #:installation-id "ins_A"
                                 #:activation other-activation))

(define grace-activation
  (issue (activation "ent_managed" "ins_A" #:valid-until "2026-05-31T23:59:00Z" #:grace 120)))
(check-true (activation-valid? managed grace-activation "ins_A" #:at "2026-06-01T00:01:00Z"))
(check-false (activation-valid? managed grace-activation "ins_A" #:at "2026-06-01T00:01:01Z"))

(define bounded (issue (entitlement "ent_bounded" (constraints #:minimum "2.0.0" #:maximum "3.0.0"))))
(check-true (version-allowed? bounded "2.5.0"))
(check-true (version-allowed? bounded "3.0.0"))
(check-false (version-allowed? bounded "3.0.1"))
(check-false (version-allowed? bounded "2.0.0-alpha"))

(define revoked-value
  (hash-set store-value
            'keys
            (hasheq 'test-2026
                    (hash-set (hash-ref (hash-ref store-value 'keys) 'test-2026) 'status "revoked"))))
(check-exn #rx"revoked"
           (lambda ()
             (verify-credential exact-envelope
                                (jsexpr->trust-store revoked-value)
                                #:at "2026-06-01T00:00:00Z")))

(check-exn #rx"unexpected credential fields"
           (lambda ()
             (validate-credential-claims
              (hash-set (entitlement "ent_typo" (constraints)) 'expires_at 'null))))
