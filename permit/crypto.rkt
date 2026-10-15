#lang racket/base

(require crypto
         (only-in crypto/libcrypto libcrypto-factory)
         racket/file
         "private/encoding.rkt")

(provide generate-ed25519-keypair
         read-ed25519-private-key
         read-ed25519-public-key
         ed25519-private-key->der
         ed25519-private-key->public-key
         ed25519-public-key->der
         ed25519-sign
         ed25519-verify
         public-key->base64
         base64->public-key)

;; Pinning the provider avoids optional FFI backends being loaded merely to
;; verify a credential. Official Racket distributions bundle OpenSSL.
(crypto-factories (list libcrypto-factory))
(define factories (list libcrypto-factory))

(define (ed25519-key? key private?)
  (and (pk-key? key)
       (or (not private?) (private-key? key))
       (let ([datum (pk-key->datum key (if private? 'rkt-private 'rkt-public))])
         (and (list? datum) (pair? datum) (eq? (car datum) 'eddsa) (member 'ed25519 datum)))))

(define (ensure-key who key private?)
  (unless (ed25519-key? key private?)
    (raise-arguments-error
     who
     (if private? "expected an Ed25519 private key" "expected an Ed25519 public key")
     "key"
     key))
  key)

(define (generate-ed25519-keypair)
  (define private-key
    (parameterize ([crypto-factories factories])
      (generate-private-key 'eddsa '((curve ed25519)))))
  (values private-key (pk-key->public-only-key private-key)))

(define (decode-key who raw formats private?)
  (define key
    (for/or ([format (in-list formats)])
      (with-handlers ([exn:fail? (lambda (_) #f)])
        (datum->pk-key raw format factories))))
  (unless key
    (raise-arguments-error who "could not decode Ed25519 key" "accepted formats" formats))
  (ensure-key who key private?))

(define (read-ed25519-private-key path)
  (decode-key 'read-ed25519-private-key
              (file->bytes path)
              '(OneAsymmetricKey PrivateKeyInfo rkt-private)
              #t))

(define (read-ed25519-public-key path)
  (decode-key 'read-ed25519-public-key
              (file->bytes path)
              '(SubjectPublicKeyInfo rkt-public openssh-public)
              #f))

(define (ed25519-private-key->der key)
  (pk-key->datum (ensure-key 'ed25519-private-key->der key #t) 'PrivateKeyInfo))

(define (ed25519-private-key->public-key key)
  (pk-key->public-only-key
   (ensure-key 'ed25519-private-key->public-key key #t)))

(define (ed25519-public-key->der key)
  (pk-key->datum (ensure-key 'ed25519-public-key->der key #f) 'SubjectPublicKeyInfo))

(define (ed25519-sign private-key message)
  (unless (bytes? message)
    (raise-argument-error 'ed25519-sign "bytes?" message))
  (pk-sign (ensure-key 'ed25519-sign private-key #t) message))

(define (ed25519-verify public-key message signature)
  (unless (bytes? message)
    (raise-argument-error 'ed25519-verify "bytes?" message))
  (unless (bytes? signature)
    (raise-argument-error 'ed25519-verify "bytes?" signature))
  (and (= (bytes-length signature) 64)
       (pk-verify (ensure-key 'ed25519-verify public-key #f) message signature)))

(define (public-key->base64 key)
  (bytes->base64 (ed25519-public-key->der key)))

(define (base64->public-key value)
  (decode-key 'base64->public-key
              (base64->bytes 'base64->public-key value)
              '(SubjectPublicKeyInfo)
              #f))
