;;; Test.SHA3.Bench — Chez Scheme FFI for benchmarking

(library (Test.SHA3.Bench foreign)
  (export performanceNow defer intToNumber)
  (import (chezscheme))

  ;; Return current monotonic time in milliseconds as a flonum.
  (define performanceNow
    (lambda ()
      (let ([t (current-time 'time-monotonic)])
        (+ (* (time-second t) 1000.0)
           (/ (time-nanosecond t) 1000000.0)))))

  ;; Force re-evaluation of a pure computation each call.
  ;; Takes (Unit -> a), returns Effect a.
  (define defer
    (lambda (thunk)
      (lambda ()
        (thunk #f))))

  ;; Int -> Number (exact->inexact)
  (define intToNumber
    (lambda (n)
      (exact->inexact n)))

) ;; end library