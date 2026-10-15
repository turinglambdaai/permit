#lang racket/base

(require json
         racket/file
         racket/list
         "credential.rkt"
         "private/json.rkt"
         "private/time.rkt"
         "identity.rkt")

(provide (struct-out local-trial)
         (struct-out local-trial-evaluation)
         make-local-trial
         local-trial->jsexpr
         jsexpr->local-trial
         read-local-trial
         write-local-trial
         evaluate-local-trial)

;; Local trials are convenience state, not signed authority. A user controlling
;; the machine can delete or roll back this state. Hosts should persist it in
;; their normal secure/local state store when nuisance resistance matters.
(struct local-trial (id started-at expires-at last-seen-at) #:transparent)
(struct local-trial-evaluation
  (active? reason expires-at remaining-seconds state applied-extension-ids)
  #:transparent)

(define state-fields '(expires_at last_seen_at protocol started_at trial_id version))

(define (fail who message . fields)
  (apply raise-arguments-error who message fields))

(define (non-empty-string? value)
  (and (string? value) (positive? (string-length value))))

(define (make-local-trial #:duration-seconds [duration (* 14 24 60 60)]
                          #:at [at (current-rfc3339)]
                          #:id [id (generate-local-trial-id)])
  (unless (exact-positive-integer? duration)
    (raise-argument-error 'make-local-trial "exact-positive-integer?" duration))
  (unless (rfc3339-utc? at)
    (raise-argument-error 'make-local-trial "canonical RFC 3339 UTC timestamp" at))
  (unless (non-empty-string? id)
    (raise-argument-error 'make-local-trial "non-empty string?" id))
  (define expires-at (seconds->rfc3339 (+ (rfc3339->seconds at) duration)))
  (local-trial id at expires-at at))

(define (local-trial->jsexpr trial)
  (unless (local-trial? trial)
    (raise-argument-error 'local-trial->jsexpr "local-trial?" trial))
  (hasheq 'protocol "permit-local-trial"
          'version 1
          'trial_id (local-trial-id trial)
          'started_at (local-trial-started-at trial)
          'expires_at (local-trial-expires-at trial)
          'last_seen_at (local-trial-last-seen-at trial)))

(define (jsexpr->local-trial value)
  (define who 'jsexpr->local-trial)
  (unless (hash? value)
    (raise-argument-error who "hash?" value))
  (define actual (sort (hash-keys value) symbol<?))
  (unless (equal? actual state-fields)
    (fail who "unexpected local trial fields" "expected" state-fields "actual" actual))
  (unless (equal? (hash-ref value 'protocol #f) "permit-local-trial")
    (fail who "invalid protocol" "value" (hash-ref value 'protocol #f)))
  (unless (equal? (hash-ref value 'version #f) 1)
    (fail who "unsupported version" "value" (hash-ref value 'version #f)))
  (define id (hash-ref value 'trial_id #f))
  (unless (non-empty-string? id)
    (fail who "invalid trial_id" "value" id))
  (for ([name (in-list '(started_at expires_at last_seen_at))])
    (unless (rfc3339-utc? (hash-ref value name #f))
      (fail who
            (format "invalid ~a" name)
            "value"
            (hash-ref value name #f))))
  (define started-at (hash-ref value 'started_at))
  (define expires-at (hash-ref value 'expires_at))
  (define last-seen-at (hash-ref value 'last_seen_at))
  (unless (rfc3339<=? started-at expires-at)
    (fail who
          "trial expiry precedes start"
          "started_at"
          started-at
          "expires_at"
          expires-at))
  (unless (rfc3339<=? started-at last-seen-at)
    (fail who
          "last_seen_at precedes trial start"
          "started_at"
          started-at
          "last_seen_at"
          last-seen-at))
  (local-trial id started-at expires-at last-seen-at))

(define (read-local-trial source)
  (jsexpr->local-trial (read-json-source/strict 'read-local-trial source)))

(define (write-local-trial trial destination)
  (define value (local-trial->jsexpr trial))
  (define (write-to out)
    (write-json value out)
    (newline out))
  (cond
    [(output-port? destination) (write-to destination)]
    [(path-string? destination)
     (call-with-output-file destination write-to #:exists 'truncate/replace)]
    [else
     (raise-argument-error 'write-local-trial
                           "(or/c output-port? path-string?)"
                           destination)]))

(define (matching-extension? trial extension issuer at)
  (unless (verified-credential? extension)
    (raise-argument-error 'evaluate-local-trial "verified-credential?" extension))
  (define claims (verified-credential-claims extension))
  (and (equal? (hash-ref claims 'type #f) "trial-extension")
       (equal? (hash-ref claims 'trial_id #f) (local-trial-id trial))
       (or (not issuer) (equal? (hash-ref claims 'issuer #f) issuer))
       (rfc3339<=? (hash-ref claims 'issued_at) at)
       (let ([not-before (hash-ref claims 'not_before)])
         (or (eq? not-before 'null) (rfc3339<=? not-before at)))))

(define (later-time left right)
  (if (rfc3339<=? left right) right left))

(define (evaluate-local-trial trial
                              #:at [at (current-rfc3339)]
                              #:extensions [extensions '()]
                              #:issuer [issuer #f]
                              #:rollback-tolerance-seconds [rollback-tolerance 300])
  (unless (local-trial? trial)
    (raise-argument-error 'evaluate-local-trial "local-trial?" trial))
  (unless (rfc3339-utc? at)
    (raise-argument-error 'evaluate-local-trial "canonical RFC 3339 UTC timestamp" at))
  (unless (and (list? extensions) (andmap verified-credential? extensions))
    (raise-argument-error 'evaluate-local-trial
                          "(listof verified-credential?)"
                          extensions))
  (unless (or (not issuer) (non-empty-string? issuer))
    (raise-argument-error 'evaluate-local-trial
                          "(or/c #f non-empty-string?)"
                          issuer))
  (unless (exact-nonnegative-integer? rollback-tolerance)
    (raise-argument-error 'evaluate-local-trial
                          "exact-nonnegative-integer?"
                          rollback-tolerance))

  (define matching
    (filter (lambda (extension)
              (matching-extension? trial extension issuer at))
            extensions))
  (define effective-expiry
    (for/fold ([expiry (local-trial-expires-at trial)])
              ([extension (in-list matching)])
      (later-time
       expiry
       (hash-ref (verified-credential-claims extension) 'use_expires_at))))

  (define now-seconds (rfc3339->seconds at))
  (define started-seconds (rfc3339->seconds (local-trial-started-at trial)))
  (define last-seen-seconds (rfc3339->seconds (local-trial-last-seen-at trial)))
  (define expires-seconds (rfc3339->seconds effective-expiry))
  (define rollback?
    (or (< (+ now-seconds rollback-tolerance) started-seconds)
        (< (+ now-seconds rollback-tolerance) last-seen-seconds)))

  (define-values (active? reason)
    (cond
      [rollback? (values #f 'clock-rollback)]
      [(> now-seconds expires-seconds) (values #f 'expired)]
      [else (values #t 'active)]))

  ;; Never move last_seen backwards. A small tolerated clock adjustment keeps
  ;; the previous high-water mark; a forward observation advances it.
  (define updated-last-seen
    (if (> now-seconds last-seen-seconds)
        at
        (local-trial-last-seen-at trial)))
  (define updated-state
    (local-trial (local-trial-id trial)
                 (local-trial-started-at trial)
                 (local-trial-expires-at trial)
                 updated-last-seen))
  (define remaining
    (max 0 (- expires-seconds now-seconds)))
  (local-trial-evaluation
   active?
   reason
   effective-expiry
   remaining
   updated-state
   (remove-duplicates (map verified-credential-id matching) string=?)))
