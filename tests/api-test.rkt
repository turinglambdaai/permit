#lang racket/base

(require rackunit
         racket/runtime-path
         "../permit/main.rkt")

(define-runtime-path credential-module "../permit/credential.rkt")
(define-runtime-path main-module "../permit/main.rkt")

(check-true (procedure? verified-credential?))
(check-true (procedure? verify-credential))

(check-true
 (procedure? (dynamic-require credential-module 'verified-credential-claims)))
(check-exn exn:fail?
           (lambda ()
             (dynamic-require credential-module 'verified-credential)))
(check-exn exn:fail?
           (lambda ()
             (dynamic-require main-module 'verified-credential-claims)))

;; Client facade intentionally omits issuer/wire constructors.
(check-exn exn:fail?
           (lambda ()
             (dynamic-require main-module 'generate-ed25519-keypair)))
(check-exn exn:fail?
           (lambda ()
             (dynamic-require main-module 'make-signed-envelope)))
(check-exn exn:fail?
           (lambda ()
             (dynamic-require main-module 'parse-credential-payload)))
