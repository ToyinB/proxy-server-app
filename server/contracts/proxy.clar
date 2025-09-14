;; Proxy Server Smart Contract
;; Implements secure delegation and upgradeable contract functionality

;; Define trait for target contracts
(define-trait proxy-target-trait
    (
        (execute-function ((list 128 uint)) (response bool uint))
    )
)

;; Constants
(define-constant contract-owner tx-sender)
(define-constant zero-address 'ST000000000000000000002AMW42H)
(define-constant err-owner-only (err u100))
(define-constant err-not-initialized (err u101))
(define-constant err-already-initialized (err u102))
(define-constant err-invalid-address (err u103))
(define-constant err-unauthorized-caller (err u104))
(define-constant err-unauthorized-function (err u105))
(define-constant err-stats-update-failed (err u106))
(define-constant err-invalid-caller (err u107))
(define-constant err-invalid-function-name (err u108))
(define-constant err-invalid-target (err u109))

;; Data Variables
(define-data-var implementation-address principal zero-address)
(define-data-var initialized bool false)

;; Data Maps
(define-map allowed-callers principal bool)
(define-map function-whitelist (string-ascii 64) bool)
(define-map call-stats principal uint)

;; Read-only functions
(define-read-only (get-implementation)
    (ok (var-get implementation-address))
)

(define-read-only (is-caller-allowed (caller principal))
    (default-to false (map-get? allowed-callers caller))
)

(define-read-only (is-function-allowed (function-name (string-ascii 64)))
    (default-to false (map-get? function-whitelist function-name))
)

(define-read-only (get-call-count (caller principal))
    (default-to u0 (map-get? call-stats caller))
)

;; Private functions
(define-private (assert-contract-owner)
    (if (is-eq tx-sender contract-owner)
        (ok true)
        err-owner-only
    )
)

(define-private (assert-initialized)
    (if (var-get initialized)
        (ok true)
        err-not-initialized
    )
)

(define-private (is-valid-caller (caller principal)) 
    (and
        (not (is-eq caller contract-owner))
        (not (is-eq caller zero-address))
    )
)

(define-private (is-valid-function-name (function-name (string-ascii 64)))
    (and 
        (> (len function-name) u0)
        (< (len function-name) u64)
    )
)

(define-private (is-valid-target (target <proxy-target-trait>))
    (let ((target-principal (contract-of target)))
        (and
            (not (is-eq target-principal zero-address))
            (not (is-eq target-principal (as-contract tx-sender)))
        )
    )
)

(define-private (increment-call-count (caller principal))
    (begin
        (map-set call-stats 
            caller 
            (+ (get-call-count caller) u1)
        )
        true
    )
)

;; Public functions
(define-public (initialize (new-implementation principal))
    (begin
        (asserts! (not (var-get initialized)) err-already-initialized)
        (asserts! (not (is-eq new-implementation zero-address)) err-invalid-address)
        (var-set implementation-address new-implementation)
        (var-set initialized true)
        (ok true)
    )
)

(define-public (upgrade-implementation (new-implementation principal))
    (begin
        (try! (assert-contract-owner))
        (try! (assert-initialized))
        (asserts! (not (is-eq new-implementation zero-address)) err-invalid-address)
        (var-set implementation-address new-implementation)
        (ok true)
    )
)

(define-public (set-allowed-caller (caller principal) (allowed bool))
    (begin
        (try! (assert-contract-owner))
        (asserts! (is-valid-caller caller) err-invalid-caller)
        (let
            ((safe-caller caller)
             (safe-allowed allowed))
            (map-set allowed-callers safe-caller safe-allowed)
            (ok true)
        )
    )
)

(define-public (set-function-whitelist (function-name (string-ascii 64)) (allowed bool))
    (begin
        (try! (assert-contract-owner))
        (asserts! (is-valid-function-name function-name) err-invalid-function-name)
        (let
            ((safe-function-name function-name)
             (safe-allowed allowed))
            (map-set function-whitelist safe-function-name safe-allowed)
            (ok true)
        )
    )
)

(define-public (forward-call (target <proxy-target-trait>) (function-name (string-ascii 64)) (args (list 128 uint)))
    (begin
        (try! (assert-initialized))
        (asserts! (is-valid-target target) err-invalid-target)
        (asserts! (is-caller-allowed tx-sender) err-unauthorized-caller)
        (asserts! (is-function-allowed function-name) err-unauthorized-function)
        
        (asserts! (increment-call-count tx-sender) err-stats-update-failed)
        
        ;; Call the target contract directly instead of using the safe-target variable
        (contract-call? target execute-function args)
    )
)

;; Fallback function to handle direct transfers
(define-public (receive)
    (begin
        (try! (assert-initialized))
        (ok true)
    )
)

;; Emergency functions
(define-public (pause-contract)
    (begin
        (try! (assert-contract-owner))
        (var-set initialized false)
        (ok true)
    )
)

(define-public (resume-contract)
    (begin
        (try! (assert-contract-owner))
        (var-set initialized true)
        (ok true)
    )
)