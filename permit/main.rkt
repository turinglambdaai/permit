#lang racket/base

(require "credential.rkt"
         "identity.rkt"
         "local-trial.rkt"
         "policy.rkt"
         "trust.rkt")

(provide verified-credential?
         verify-credential
         (struct-out exn:fail:permit)
         (struct-out exn:fail:permit:verify)
         verify-failure-reasons
         verified-credential-type
         verified-credential-id
         verified-credential-issuer
         verified-credential-issued-at
         verified-credential-entitlement-id
         verified-credential-revision
         verified-credential-subject-type
         verified-credential-subject-id
         verified-credential-subject-display
         verified-credential-channel
         verified-credential-use-expires-at
         verified-credential-updates-through
         verified-credential-features-through
         select-latest-entitlement

         credential-usable?
         credential-status
         activation-valid?
         trial-extension-valid?
         feature-entitled?
         addon-entitled?
         edition-entitled?
         update-entitled?
         capability-value
         limit-value
         version-allowed?

         trust-store?
         trust-store-issuer
         read-trust-store
         jsexpr->trust-store

         generate-installation-id
         generate-local-trial-id

         local-trial?
         local-trial-id
         local-trial-started-at
         local-trial-expires-at
         local-trial-last-seen-at
         local-trial-evaluation?
         local-trial-evaluation-active?
         local-trial-evaluation-reason
         local-trial-evaluation-expires-at
         local-trial-evaluation-remaining-seconds
         local-trial-evaluation-state
         local-trial-evaluation-applied-extension-ids
         make-local-trial
         local-trial->jsexpr
         jsexpr->local-trial
         read-local-trial
         write-local-trial
         evaluate-local-trial)
