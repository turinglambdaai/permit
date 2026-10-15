#lang racket/base

(require rackunit
         racket/runtime-path
         "../permit/main.rkt")

(define-runtime-path credential-module "../permit/credential.rkt")

(check-true (procedure? verified-credential?))
(check-true (procedure? verified-credential-claims))
(check-true (procedure? verify-credential))

(check-exn exn:fail?
           (lambda ()
             (dynamic-require credential-module 'verified-credential)))
