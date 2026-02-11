;;; Crypto.Keccak — Optimized Chez Scheme FFI
;;;
;;; Keccak-f[1600] permutation and sponge construction using mutable vectors.
;;; State is a vector of 25 native 64-bit integers. Chez Scheme handles
;;; these as fixnums (up to 60 bits) or bignums transparently.

(library (Crypto.Keccak foreign)
  (export roundConstants orInt spongeOptimized keccakF1600Optimized)
  (import (chezscheme)
          (srfi :214))

  (define mask64 #xFFFFFFFFFFFFFFFF)

  ;; ── Round Constants ────────────────────────────────────────────────────

  (define roundConstants
    (list->flexvector
      (list
        #x0000000000000001 #x0000000000008082 #x800000000000808A
        #x8000000080008000 #x000000000000808B #x0000000080000001
        #x8000000080008081 #x8000000000008009 #x000000000000008A
        #x0000000000000088 #x0000000080008009 #x000000008000000A
        #x000000008000808B #x800000000000008B #x8000000000008089
        #x8000000000008003 #x8000000000008002 #x8000000000000080
        #x000000000000800A #x800000008000000A #x8000000080008081
        #x8000000000008080 #x0000000080000001 #x8000000080008008)))

  (define orInt
    (lambda (a)
      (lambda (b)
        (logior a b))))

  ;; ── Helpers ────────────────────────────────────────────────────────────

  (define-syntax xor64
    (syntax-rules ()
      [(_ a b) (logand (logxor a b) mask64)]))

  (define-syntax and64
    (syntax-rules ()
      [(_ a b) (logand a b)]))

  (define-syntax not64
    (syntax-rules ()
      [(_ a) (logand (lognot a) mask64)]))

  (define-syntax rotl64
    (syntax-rules ()
      [(_ x n)
       (if (= n 0) x
           (logand (logior (ash x n) (ash x (- n 64))) mask64))]))

  ;; ── ρ offsets ──────────────────────────────────────────────────────────

  (define rho-offsets
    '#( 0  1 62 28 27
       36 44  6 55 20
        3 10 43 25 39
       41 45 15 21  8
       18  2 61 56 14))

  ;; ── Round constants as a native vector for fast access ─────────────────

  (define rc-vec
    '#( #x0000000000000001 #x0000000000008082 #x800000000000808A
        #x8000000080008000 #x000000000000808B #x0000000080000001
        #x8000000080008081 #x8000000000008009 #x000000000000008A
        #x0000000000000088 #x0000000080008009 #x000000008000000A
        #x000000008000808B #x800000000000008B #x8000000000008089
        #x8000000000008003 #x8000000000008002 #x8000000000000080
        #x000000000000800A #x800000008000000A #x8000000080008081
        #x8000000000008080 #x0000000080000001 #x8000000080008008))

  ;; ── Keccak-f[1600] on a mutable vector(25) ────────────────────────────

  (define (keccak-f! s)
    (let ([c (make-vector 5)]
          [d (make-vector 5)]
          [b (make-vector 25)])
      (do ([round 0 (+ round 1)])
          ((= round 24))

        ;; ── θ ──────────────────────────────────────────────────────
        (do ([x 0 (+ x 1)])
            ((= x 5))
          (vector-set! c x
            (xor64
              (xor64 (vector-ref s x)
                     (vector-ref s (+ x 5)))
              (xor64 (vector-ref s (+ x 10))
                     (xor64 (vector-ref s (+ x 15))
                            (vector-ref s (+ x 20)))))))

        (do ([x 0 (+ x 1)])
            ((= x 5))
          (vector-set! d x
            (xor64
              (vector-ref c (mod (+ x 4) 5))
              (rotl64 (vector-ref c (mod (+ x 1) 5)) 1))))

        (do ([i 0 (+ i 1)])
            ((= i 25))
          (vector-set! s i
            (xor64 (vector-ref s i)
                   (vector-ref d (mod i 5)))))

        ;; ── ρ + π ──────────────────────────────────────────────────
        (do ([i 0 (+ i 1)])
            ((= i 25))
          (let* ([x (mod i 5)]
                 [y (div i 5)]
                 [src-x (mod (+ x (* 3 y)) 5)]
                 [src-idx (+ src-x (* x 5))])
            (vector-set! b i
              (rotl64 (vector-ref s src-idx)
                      (vector-ref rho-offsets src-idx)))))

        ;; ── χ ──────────────────────────────────────────────────────
        (do ([y 0 (+ y 5)])
            ((= y 25))
          (do ([x 0 (+ x 1)])
              ((= x 5))
            (vector-set! s (+ y x)
              (xor64
                (vector-ref b (+ y x))
                (and64
                  (not64 (vector-ref b (+ y (mod (+ x 1) 5))))
                  (vector-ref b (+ y (mod (+ x 2) 5))))))))

        ;; ── ι ──────────────────────────────────────────────────────
        (vector-set! s 0
          (xor64 (vector-ref s 0) (vector-ref rc-vec round))))))

  ;; ── Byte ↔ Word64 helpers ─────────────────────────────────────────────

  (define (bytes-to-lane bv offset)
    (let ([b0 (bytevector-u8-ref bv offset)]
          [b1 (bytevector-u8-ref bv (+ offset 1))]
          [b2 (bytevector-u8-ref bv (+ offset 2))]
          [b3 (bytevector-u8-ref bv (+ offset 3))]
          [b4 (bytevector-u8-ref bv (+ offset 4))]
          [b5 (bytevector-u8-ref bv (+ offset 5))]
          [b6 (bytevector-u8-ref bv (+ offset 6))]
          [b7 (bytevector-u8-ref bv (+ offset 7))])
      (logior b0
        (logior (ash b1 8)
          (logior (ash b2 16)
            (logior (ash b3 24)
              (logior (ash b4 32)
                (logior (ash b5 40)
                  (logior (ash b6 48)
                    (ash b7 56))))))))))

  ;; ── Sponge (optimized, bytevector-native) ─────────────────────────────

  (define spongeOptimized
    (lambda (rate-bytes)
      (lambda (suffix-byte)
        (lambda (output-bytes)
          (lambda (message-fv)
            (let* ([msg-len (flexvector-length message-fv)]
                   [msg (make-bytevector msg-len)]
                   [_ (do ([i 0 (+ i 1)])
                          ((= i msg-len))
                        (bytevector-u8-set! msg i (flexvector-ref message-fv i)))]
                   ;; Padding
                   [q (- rate-bytes (mod msg-len rate-bytes))]
                   [padded-len (+ msg-len q)]
                   [padded (make-bytevector padded-len 0)]
                   [_ (bytevector-copy! msg 0 padded 0 msg-len)]
                   [_ (if (= q 1)
                          (bytevector-u8-set! padded msg-len
                            (logior suffix-byte #x80))
                          (begin
                            (bytevector-u8-set! padded msg-len suffix-byte)
                            (bytevector-u8-set! padded (- padded-len 1) #x80)))]
                   ;; State
                   [s (make-vector 25 0)]
                   [num-lanes (div rate-bytes 8)]
                   [num-blocks (div padded-len rate-bytes)])

              ;; ── Absorb ───────────────────────────────────────────
              (do ([blk 0 (+ blk 1)])
                  ((= blk num-blocks))
                (let ([off (* blk rate-bytes)])
                  (do ([lane 0 (+ lane 1)])
                      ((= lane num-lanes))
                    (vector-set! s lane
                      (xor64 (vector-ref s lane)
                             (bytes-to-lane padded (+ off (* lane 8))))))
                  (keccak-f! s)))

              ;; ── Squeeze ──────────────────────────────────────────
              (let ([out-bv (make-bytevector output-bytes)])
                (let loop ([pos 0])
                  (when (< pos output-bytes)
                    (do ([lane 0 (+ lane 1)])
                        ((or (= lane num-lanes) (>= (+ pos (* lane 8)) output-bytes)))
                      (let ([base (+ pos (* lane 8))]
                            [w (vector-ref s lane)])
                        (do ([b 0 (+ b 1)])
                            ((or (= b 8) (>= (+ base b) output-bytes)))
                          (bytevector-u8-set! out-bv (+ base b)
                            (logand (ash w (* b -8)) #xFF)))))
                    (let ([next-pos (+ pos rate-bytes)])
                      (when (< next-pos output-bytes)
                        (keccak-f! s))
                      (loop next-pos))))

                ;; Convert bytevector → flexvector for PureScript
                (let ([result (make-flexvector output-bytes)])
                  (do ([i 0 (+ i 1)])
                      ((= i output-bytes) result)
                    (flexvector-set! result i
                      (bytevector-u8-ref out-bv i)))))))))))

  ;; ── keccakF1600 wrapper for PureScript State type ─────────────────────

  (define keccakF1600Optimized
    (lambda (state-fv)
      (let ([s (make-vector 25)])
        (do ([i 0 (+ i 1)])
            ((= i 25))
          (vector-set! s i (flexvector-ref state-fv i)))
        (keccak-f! s)
        (let ([result (make-flexvector 25)])
          (do ([i 0 (+ i 1)])
              ((= i 25) result)
            (flexvector-set! result i (vector-ref s i)))))))

) ;; end library