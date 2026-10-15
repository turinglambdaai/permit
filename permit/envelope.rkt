#lang racket/base

(require json
         "crypto.rkt"
         "private/encoding.rkt")

(provide (struct-out permit-envelope)
         make-signed-envelope
         envelope->jsexpr
         jsexpr->envelope
         read-envelope
         write-envelope
         verify-envelope-signature)

(struct permit-envelope (key-id payload signature) #:transparent)

(define envelope-fields '(algorithm key_id payload permit_version signature))

(define (read-complete-json who in)
  (define value (read-json in))
  (define trailing (read-json in))
  (unless (eof-object? trailing)
    (raise-arguments-error who "input must contain exactly one JSON value"))
  value)

(define (make-signed-envelope key-id payload private-key)
  (unless (and (string? key-id) (positive? (string-length key-id)))
    (raise-argument-error 'make-signed-envelope "non-empty-string?" key-id))
  (unless (bytes? payload)
    (raise-argument-error 'make-signed-envelope "bytes?" payload))
  (permit-envelope key-id payload (ed25519-sign private-key payload)))

(define (envelope->jsexpr envelope)
  (hasheq 'permit_version
          1
          'algorithm
          "Ed25519"
          'key_id
          (permit-envelope-key-id envelope)
          'payload
          (bytes->base64 (permit-envelope-payload envelope))
          'signature
          (bytes->base64 (permit-envelope-signature envelope))))

(define (jsexpr->envelope value)
  (unless (hash? value)
    (raise-argument-error 'jsexpr->envelope "hash?" value))
  (define fields (sort (hash-keys value) symbol<?))
  (unless (equal? fields envelope-fields)
    (raise-arguments-error 'jsexpr->envelope
                           "unexpected envelope fields"
                           "expected"
                           envelope-fields
                           "actual"
                           fields))
  (unless (equal? (hash-ref value 'permit_version #f) 1)
    (raise-arguments-error 'jsexpr->envelope
                           "unsupported permit_version"
                           "value"
                           (hash-ref value 'permit_version #f)))
  (unless (equal? (hash-ref value 'algorithm #f) "Ed25519")
    (raise-arguments-error 'jsexpr->envelope
                           "unsupported algorithm"
                           "value"
                           (hash-ref value 'algorithm #f)))
  (define key-id (hash-ref value 'key_id #f))
  (unless (and (string? key-id) (positive? (string-length key-id)))
    (raise-arguments-error 'jsexpr->envelope "invalid key_id" "value" key-id))
  (define payload (base64->bytes 'jsexpr->envelope (hash-ref value 'payload #f)))
  (define signature (base64->bytes 'jsexpr->envelope (hash-ref value 'signature #f)))
  (unless (= (bytes-length signature) 64)
    (raise-arguments-error 'jsexpr->envelope
                           "Ed25519 signature must be 64 bytes"
                           "length"
                           (bytes-length signature)))
  (permit-envelope key-id payload signature))

(define (read-envelope source)
  (define value
    (cond
      [(input-port? source) (read-complete-json 'read-envelope source)]
      [(path-string? source)
       (call-with-input-file source
         (lambda (in) (read-complete-json 'read-envelope in))
         #:mode 'text)]
      [else (raise-argument-error 'read-envelope "(or/c input-port? path-string?)" source)]))
  (jsexpr->envelope value))

(define (write-envelope envelope destination)
  (define (write-to out)
    (write-json (envelope->jsexpr envelope) out)
    (newline out))
  (cond
    [(output-port? destination) (write-to destination)]
    [(path-string? destination)
     (call-with-output-file destination write-to #:exists 'truncate/replace)]
    [else (raise-argument-error 'write-envelope "(or/c output-port? path-string?)" destination)]))

(define (verify-envelope-signature envelope public-key)
  (ed25519-verify public-key
                  (permit-envelope-payload envelope)
                  (permit-envelope-signature envelope)))
