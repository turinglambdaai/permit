#lang racket/base

(require rackunit
         "../permit/private/json.rkt")

(test-case "strict JSON accepts valid scalar roots"
  (check-equal? (read-json-bytes/strict 'test #" 123 \n") 123)
  (check-equal? (read-json-bytes/strict 'test #"-1.25e+2") -125.0)
  (check-equal? (read-json-bytes/strict 'test #"true") #t)
  (check-equal? (read-json-bytes/strict 'test #"null") 'null))

(test-case "strict JSON rejects partial root and nested scalar parses"
  (for ([raw (in-list (list #"123x" #"truegarbage" #"nullx"
                            #"01" #"1." #"-" #"1e"
                            #"[123x]" #"{\"value\":123x}"
                            #"[truegarbage]" #"{\"a\":falsex}"))])
    (check-exn exn:fail?
               (lambda () (read-json-bytes/strict 'test raw)))))
