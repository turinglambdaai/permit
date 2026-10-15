#lang racket/base

(require racket/date
         racket/format)

(provide rfc3339-utc?
         rfc3339<=?
         rfc3339->seconds
         current-rfc3339)

(define timestamp-rx
  #px"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")

(define (rfc3339-utc? value)
  (and (string? value)
       (regexp-match? timestamp-rx value)
       (with-handlers ([exn:fail? (lambda (_) #f)])
         (equal? value (seconds->rfc3339 (rfc3339->seconds value))))))

(define (rfc3339->seconds value)
  (define match (and (string? value) (regexp-match timestamp-rx value)))
  (unless match
    (raise-argument-error 'rfc3339->seconds "canonical RFC 3339 UTC timestamp" value))
  (define parts (map string->number (regexp-match* #px"[0-9]+" value)))
  (apply find-seconds
         (list (list-ref parts 5)
               (list-ref parts 4)
               (list-ref parts 3)
               (list-ref parts 2)
               (list-ref parts 1)
               (list-ref parts 0)
               #f)))

;; Canonical fixed-width UTC timestamps sort chronologically as strings.
(define (rfc3339<=? left right)
  (unless (rfc3339-utc? left)
    (raise-argument-error 'rfc3339<=? "canonical RFC 3339 UTC timestamp" left))
  (unless (rfc3339-utc? right)
    (raise-argument-error 'rfc3339<=? "canonical RFC 3339 UTC timestamp" right))
  (or (string=? left right) (string<? left right)))

(define (pad value width)
  (~r value #:min-width width #:pad-string "0"))

(define (current-rfc3339)
  (seconds->rfc3339 (current-seconds)))

(define (seconds->rfc3339 seconds)
  (define now (seconds->date seconds #f))
  (string-append (pad (date-year now) 4)
                 "-"
                 (pad (date-month now) 2)
                 "-"
                 (pad (date-day now) 2)
                 "T"
                 (pad (date-hour now) 2)
                 ":"
                 (pad (date-minute now) 2)
                 ":"
                 (pad (date-second now) 2)
                 "Z"))
