#lang racket/base

(require rackunit
         racket/file
         racket/runtime-path
         "../permit/main.rkt")

(define-runtime-path examples-root "../examples")

(for ([name (in-list '("perpetual.json"
                       "maintenance.json"
                       "feature-window.json"
                       "subscription.json"
                       "team-managed.json"
                       "trial.json"))])
  (define payload (file->bytes (build-path examples-root name)))
  (check-not-exn
   (lambda () (parse-credential-payload payload))
   (format "example payload should validate: ~a" name)))
