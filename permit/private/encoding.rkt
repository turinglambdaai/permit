#lang racket/base

(require net/base64
         racket/string)

(provide bytes->base64
         base64->bytes)

(define (bytes->base64 value)
  (bytes->string/utf-8 (base64-encode value #"")))

(define (base64->bytes who value)
  (unless (string? value)
    (raise-argument-error who "string?" value))
  (unless (and (zero? (modulo (string-length value) 4))
               (regexp-match? #px"^[A-Za-z0-9+/]*={0,2}$" value))
    (raise-arguments-error who "invalid base64" "value" value))
  (with-handlers ([exn:fail? (lambda (_) (raise-arguments-error who "invalid base64" "value" value))])
    (base64-decode (string->bytes/utf-8 value))))
