#lang racket/base

(require racket/list
         racket/string)

(provide semver?
         semver-compare
         semver<=?)

(struct parsed-semver (major minor patch prerelease) #:transparent)

(define semver-rx
  #px"^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$")

(define (numeric-id? value)
  (regexp-match? #px"^[0-9]+$" value))

(define (valid-prerelease-id? value)
  (and (positive? (string-length value))
       (or (not (numeric-id? value))
           (string=? value "0")
           (not (char=? (string-ref value 0) #\0)))))

(define (parse-semver who value)
  (define match (and (string? value) (regexp-match semver-rx value)))
  (unless match
    (raise-argument-error who "SemVer 2.0 string" value))
  (define prerelease-text (list-ref match 4))
  (define prerelease
    (and prerelease-text (string-split prerelease-text ".")))
  (when (and prerelease (not (andmap valid-prerelease-id? prerelease)))
    (raise-argument-error who "SemVer 2.0 string" value))
  (parsed-semver (string->number (list-ref match 1))
                 (string->number (list-ref match 2))
                 (string->number (list-ref match 3))
                 prerelease))

(define (semver? value)
  (with-handlers ([exn:fail? (lambda (_) #f)])
    (parse-semver 'semver? value)
    #t))

(define (compare-number left right)
  (cond
    [(< left right) -1]
    [(> left right) 1]
    [else 0]))

(define (compare-prerelease-id left right)
  (define left-number (and (numeric-id? left) (string->number left)))
  (define right-number (and (numeric-id? right) (string->number right)))
  (cond
    [(and left-number right-number) (compare-number left-number right-number)]
    [left-number -1]
    [right-number 1]
    [(string<? left right) -1]
    [(string>? left right) 1]
    [else 0]))

(define (compare-prerelease left right)
  (cond
    [(and (not left) (not right)) 0]
    [(not left) 1]
    [(not right) -1]
    [else
     (let loop ([left left] [right right])
       (cond
         [(and (null? left) (null? right)) 0]
         [(null? left) -1]
         [(null? right) 1]
         [else
          (define result (compare-prerelease-id (car left) (car right)))
          (if (zero? result)
              (loop (cdr left) (cdr right))
              result)]))]))

(define (semver-compare left right)
  (define left* (parse-semver 'semver-compare left))
  (define right* (parse-semver 'semver-compare right))
  (define major (compare-number (parsed-semver-major left*) (parsed-semver-major right*)))
  (define minor (compare-number (parsed-semver-minor left*) (parsed-semver-minor right*)))
  (define patch (compare-number (parsed-semver-patch left*) (parsed-semver-patch right*)))
  (cond
    [(not (zero? major)) major]
    [(not (zero? minor)) minor]
    [(not (zero? patch)) patch]
    [else (compare-prerelease (parsed-semver-prerelease left*)
                              (parsed-semver-prerelease right*))]))

(define (semver<=? left right)
  (<= (semver-compare left right) 0))
