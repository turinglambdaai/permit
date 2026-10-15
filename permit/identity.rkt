#lang racket/base

(require racket/format
         racket/random)

(provide generate-installation-id
         generate-local-trial-id)

(define (random-hex bytes-count)
  (apply string-append
         (for/list ([byte (in-bytes (crypto-random-bytes bytes-count))])
           (~r byte #:base 16 #:min-width 2 #:pad-string "0"))))

(define (generate-installation-id)
  (string-append "ins_" (random-hex 16)))

(define (generate-local-trial-id)
  (string-append "trial_" (random-hex 16)))
