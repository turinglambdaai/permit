#lang racket/base

;; Typed refusals shared by the verifier and the issuer (decisions 0001 and
;; 0002). A refusal is always an exception — fail-closed never returns a
;; value — and carries a reason symbol so adapters record and translate it
;; without parsing message text. Messages keep the raise-arguments-error
;; layout ("who: message\n  field: value") for callers that still match them.

(provide (struct-out exn:fail:permit)
         (struct-out exn:fail:permit:verify)
         (struct-out exn:fail:permit:issue)
         verify-failure-reasons
         issue-failure-reasons
         raise-verify-error
         raise-issue-error
         rewrap-as-verify-error
         rewrap-as-issue-error)

(struct exn:fail:permit exn:fail (reason) #:transparent)
(struct exn:fail:permit:verify exn:fail:permit () #:transparent)
(struct exn:fail:permit:issue exn:fail:permit () #:transparent)

;; Pipeline order: a conforming verifier checks these in sequence, so the
;; reason also names the guard that refused.
(define verify-failure-reasons
  '(envelope key-unknown key-revoked signature schema issuer key-window key-purpose))

(define issue-failure-reasons
  '(schema issuer key-unknown key-status key-window key-purpose key-mismatch))

(define (format-message who message fields)
  (define detail
    (let loop ([fields fields] [acc '()])
      (if (or (null? fields) (null? (cdr fields)))
          (reverse acc)
          (loop (cddr fields)
                (cons (format "\n  ~a: ~v" (car fields) (cadr fields)) acc)))))
  (apply string-append (format "~a: ~a" who message) detail))

(define (raise-verify-error reason message . fields)
  (raise (exn:fail:permit:verify (format-message 'verify-credential message fields)
                                 (current-continuation-marks)
                                 reason)))

(define (raise-issue-error reason message . fields)
  (raise (exn:fail:permit:issue (format-message 'issue-credential message fields)
                                (current-continuation-marks)
                                reason)))

;; Lower layers (envelope reader, strict JSON, schema) raise their own
;; contract errors; the pipeline attributes them to the stage that ran them.
(define (rewrap-as-verify-error reason thunk)
  (with-handlers ([exn:fail:permit? raise]
                  [exn:fail?
                   (lambda (e)
                     (raise (exn:fail:permit:verify (exn-message e)
                                                    (exn-continuation-marks e)
                                                    reason)))])
    (thunk)))

(define (rewrap-as-issue-error reason thunk)
  (with-handlers ([exn:fail:permit? raise]
                  [exn:fail?
                   (lambda (e)
                     (raise (exn:fail:permit:issue (exn-message e)
                                                   (exn-continuation-marks e)
                                                   reason)))])
    (thunk)))
