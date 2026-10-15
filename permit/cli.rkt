#lang racket/base

(require json
         racket/cmdline
         racket/file
         racket/port
         racket/string
         "credential.rkt"
         "crypto.rkt"
         "envelope.rkt"
         "policy.rkt"
         "private/time.rkt"
         "schema.rkt"
         "trust.rkt")

(provide run-cli)

(define (die message)
  (eprintf "permit: ~a\n" message)
  (exit 2))

(define (write-json-line value [out (current-output-port)])
  (write-json value out)
  (newline out))

(define (require-option command name value)
  (unless value
    (die (format "~a requires ~a" command name)))
  value)

(define (keygen args)
  (define private-path #f)
  (define public-path #f)
  (define trust-path #f)
  (define key-id #f)
  (define issuer #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line #:program "raco permit keygen"
                  #:once-each
                  [("--private") path "Private key output (PKCS#8 DER)" (set! private-path path)]
                  [("--public") path "Public key output (SPKI DER)" (set! public-path path)]
                  [("--trust-store") path "Optional trust-store JSON output" (set! trust-path path)]
                  [("--key-id") value "Key identifier for trust store" (set! key-id value)]
                  [("--issuer") value "Issuer for trust store" (set! issuer value)]))
  (require-option 'keygen "--private" private-path)
  (require-option 'keygen "--public" public-path)
  (when trust-path
    (require-option 'keygen "--key-id" key-id)
    (require-option 'keygen "--issuer" issuer))
  (define-values (private-key public-key) (generate-ed25519-keypair))
  (call-with-output-file private-path
                         (lambda (out) (write-bytes (ed25519-private-key->der private-key) out))
                         #:mode 'binary
                         #:exists 'error)
  (call-with-output-file public-path
                         (lambda (out) (write-bytes (ed25519-public-key->der public-key) out))
                         #:mode 'binary
                         #:exists 'error)
  (when trust-path
    (define store
      (hasheq 'protocol
              "permit-trust-store"
              'version
              1
              'issuer
              issuer
              'keys
              (hash (string->symbol key-id)
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
    (call-with-output-file trust-path (lambda (out) (write-json-line store out)) #:exists 'error))
  (write-json-line
   (hasheq 'private_key private-path 'public_key public-path 'trust_store (or trust-path 'null))))

(define (sign-command args)
  (define key-path #f)
  (define key-id #f)
  (define payload-path #f)
  (define output-path #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line #:program "raco permit sign"
                  #:once-each [("--key") path "Ed25519 private key" (set! key-path path)]
                  [("--key-id") value "Trust-store key identifier" (set! key-id value)]
                  [("--payload") path "Credential payload JSON" (set! payload-path path)]
                  [("--output") path "Signed envelope output" (set! output-path path)]))
  (for ([entry (in-list (list (cons "--key" key-path)
                              (cons "--key-id" key-id)
                              (cons "--payload" payload-path)
                              (cons "--output" output-path)))])
    (require-option 'sign (car entry) (cdr entry)))
  (define payload (file->bytes payload-path))
  ;; Signing invalid claims would produce authentic but unusable credentials.
  (parse-credential-payload payload)
  (define envelope (make-signed-envelope key-id payload (read-ed25519-private-key key-path)))
  (write-envelope envelope output-path)
  (write-json-line
   (hasheq 'credential output-path 'key_id key-id 'payload_bytes (bytes-length payload))))

(define (load-verified command store-path credential-path at)
  (require-option command "--trust-store" store-path)
  (require-option command "--credential" credential-path)
  (verify-credential credential-path (read-trust-store store-path) #:at at))

(define (verify-command args)
  (define store-path #f)
  (define credential-path #f)
  (define payload-output #f)
  (define at (current-rfc3339))
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit verify"
     #:once-each [("--trust-store") path "Trust-store JSON" (set! store-path path)]
     [("--credential") path "Signed credential" (set! credential-path path)]
     [("--at") value "Verification time" (set! at value)]
     [("--payload-out") path "Write exact verified payload bytes" (set! payload-output path)]))
  (define credential (load-verified 'verify store-path credential-path at))
  (when payload-output
    (call-with-output-file payload-output
                           (lambda (out) (write-bytes (verified-credential-payload credential) out))
                           #:mode 'binary
                           #:exists 'truncate/replace))
  (write-json-line (hasheq 'valid
                           #t
                           'credential_id
                           (verified-credential-id credential)
                           'type
                           (verified-credential-type credential)
                           'key_id
                           (verified-credential-key-id credential))))

(define (inspect-command args)
  (define credential-path #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line #:program "raco permit inspect"
                  #:once-each
                  [("--credential") path "Signed credential" (set! credential-path path)]))
  (require-option 'inspect "--credential" credential-path)
  (define envelope (read-envelope credential-path))
  (define claims (parse-credential-payload (permit-envelope-payload envelope)))
  (write-json-line (hasheq 'warning
                           "UNVERIFIED: use `permit verify` before trusting these claims"
                           'key_id
                           (permit-envelope-key-id envelope)
                           'claims
                           claims)))

(define (check-command args)
  (define store-path #f)
  (define credential-path #f)
  (define activation-path #f)
  (define product #f)
  (define feature #f)
  (define edition #f)
  (define update-published-at #f)
  (define feature-published-at #f)
  (define installation-id #f)
  (define version #f)
  (define at (current-rfc3339))
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit check"
     #:once-each [("--trust-store") path "Trust-store JSON" (set! store-path path)]
     [("--credential") path "Signed entitlement or trial" (set! credential-path path)]
     [("--activation") path "Optional signed activation lease" (set! activation-path path)]
     [("--product") value "Product identifier" (set! product value)]
     [("--feature") value "Feature to evaluate" (set! feature value)]
     [("--edition") value "Edition to evaluate" (set! edition value)]
     [("--update-published-at") value "Release publication time" (set! update-published-at value)]
     [("--feature-published-at") value "Feature publication time" (set! feature-published-at value)]
     [("--installation-id")
      value
      "Stable application installation identifier"
      (set! installation-id value)]
     [("--version") value "Application version" (set! version value)]
     [("--at") value "Policy evaluation time" (set! at value)]))
  (define store (read-trust-store (require-option 'check "--trust-store" store-path)))
  (define credential
    (verify-credential (require-option 'check "--credential" credential-path) store #:at at))
  (define activation (and activation-path (verify-credential activation-path store #:at at)))
  (define status
    (credential-status credential #:at at #:installation-id installation-id #:activation activation))
  (define result
    (hash-set*
     status
     'credential_id
     (verified-credential-id credential)
     'type
     (verified-credential-type credential)
     'feature_allowed
     (if feature
         (feature-entitled? credential
                            (require-option 'check "--product with --feature" product)
                            feature
                            #:published-at feature-published-at
                            #:at at
                            #:version version
                            #:installation-id installation-id
                            #:activation activation)
         'null)
     'edition_allowed
     (if edition
         (edition-entitled? credential
                            (require-option 'check "--product with --edition" product)
                            edition
                            #:at at
                            #:version version
                            #:installation-id installation-id
                            #:activation activation)
         'null)
     'update_allowed
     (if update-published-at
         (update-entitled? credential
                           (require-option 'check "--product with --update-published-at" product)
                           update-published-at
                           #:at at
                           #:version version
                           #:installation-id installation-id
                           #:activation activation)
         'null)))
  (write-json-line result))

(define (usage)
  (displayln "Permit — signed entitlements for independent software")
  (displayln "usage: raco permit <keygen|sign|verify|inspect|check> [options]"))

(define (run-cli [args (vector->list (current-command-line-arguments))])
  (with-handlers ([exn:fail? (lambda (e)
                               (eprintf "permit: ~a\n" (exn-message e))
                               (exit 1))])
    (cond
      [(null? args) (usage)]
      [else
       (case (string->symbol (car args))
         [(keygen) (keygen (cdr args))]
         [(sign) (sign-command (cdr args))]
         [(verify) (verify-command (cdr args))]
         [(inspect) (inspect-command (cdr args))]
         [(check) (check-command (cdr args))]
         [(help --help -h) (usage)]
         [else (die (format "unknown command: ~a" (car args)))])])))

(module+ main
  (run-cli))
