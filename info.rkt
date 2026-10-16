#lang info

(define collection 'multi)
(define deps '("base" "crypto-lib" "net-lib" "rackunit-lib"))
(define build-deps '("racket-doc" "scribble-lib"))
(define pkg-desc "Offline-verifiable, online-manageable signed entitlements")
(define version "0.1")
(define pkg-authors '(turinglambdaai))
(define license 'Apache-2.0)
(define raco-commands
  '(("permit" permit/raco "issue and verify Permit credentials" #f)))
