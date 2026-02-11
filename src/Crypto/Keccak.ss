;;; Crypto.Keccak — Optimized Chez Scheme FFI (32-bit interleaved, fixnum-only)
;;;
;;; Keccak-f[1600] using 50 fixnums (25 lanes × hi/lo 32-bit halves).
;;; Right shifts use fxsrl (always safe). Left shifts use ash + logand
;;; because fxsll overflows when a 32-bit value is shifted past 2^60.

(library (Crypto.Keccak foreign)
  (export roundConstants orInt spongeOptimized keccakF1600Optimized)
  (import (chezscheme)
          (srfi :214))

  (define mask32 #xFFFFFFFF)

  ;; ── Safe 32-bit left shift ─────────────────────────────────────────────
  ;; fxsll overflows when result > 2^60. ash handles arbitrary precision,
  ;; logand mask32 brings it back to a fixnum.
  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (logand (ash x n) mask32)]))

  ;; ── Legacy exports ─────────────────────────────────────────────────────

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

  ;; ── Round constants as hi/lo 32-bit vectors ────────────────────────────

  (define rc-hi
    '#(#x00000000 #x00000000 #x80000000 #x80000000
       #x00000000 #x00000000 #x80000000 #x80000000
       #x00000000 #x00000000 #x00000000 #x00000000
       #x00000000 #x80000000 #x80000000 #x80000000
       #x80000000 #x80000000 #x00000000 #x80000000
       #x80000000 #x80000000 #x00000000 #x80000000))

  (define rc-lo
    '#(#x00000001 #x00008082 #x0000808A #x80008000
       #x0000808B #x80000001 #x80008081 #x00008009
       #x0000008A #x00000088 #x80008009 #x8000000A
       #x8000808B #x0000008B #x00008089 #x00008003
       #x00008002 #x00000080 #x0000800A #x8000000A
       #x80008081 #x00008080 #x80000001 #x80008008))

  ;; ── ρ offsets ──────────────────────────────────────────────────────────

  (define rho-offsets
    '#( 0  1 62 28 27
       36 44  6 55 20
        3 10 43 25 39
       41 45 15 21  8
       18  2 61 56 14))

  ;; ── π source lane table ────────────────────────────────────────────────

  (define pi-lanes
    '#(0 10 20 5 15 16 1 11 21 6 7 17 2 12 22 23 8 18 3 13 14 24 9 19 4))

  ;; ── Keccak-f[1600] on mutable vector(50) of fixnums ──────────────────
  ;; Layout: s[2*i] = hi32, s[2*i+1] = lo32 for lane i.

  (define (keccak-f! s)
    (let ([c (make-vector 10)]
          [d (make-vector 10)]
          [b (make-vector 50)])
      (do ([round 0 (fx+ round 1)])
          ((fx= round 24))

        ;; ── θ: column parities ─────────────────────────────────────
        (do ([x 0 (fx+ x 1)])
            ((fx= x 5))
          (let ([x2 (fx* x 2)])
            (vector-set! c x2
              (fxlogand
                (fxlogxor
                  (fxlogxor (vector-ref s x2) (vector-ref s (fx+ x2 10)))
                  (fxlogxor (vector-ref s (fx+ x2 20))
                    (fxlogxor (vector-ref s (fx+ x2 30))
                              (vector-ref s (fx+ x2 40)))))
                mask32))
            (let ([x2+1 (fx+ x2 1)])
              (vector-set! c x2+1
                (fxlogand
                  (fxlogxor
                    (fxlogxor (vector-ref s x2+1) (vector-ref s (fx+ x2+1 10)))
                    (fxlogxor (vector-ref s (fx+ x2+1 20))
                      (fxlogxor (vector-ref s (fx+ x2+1 30))
                                (vector-ref s (fx+ x2+1 40)))))
                  mask32)))))

        ;; θ: d[x] = c[(x+4)%5] XOR rotl(c[(x+1)%5], 1)
        (do ([x 0 (fx+ x 1)])
            ((fx= x 5))
          (let* ([x2 (fx* x 2)]
                 [prev (fx* (fxmod (fx+ x 4) 5) 2)]
                 [next (fx* (fxmod (fx+ x 1) 5) 2)]
                 [ch (vector-ref c next)]
                 [cl (vector-ref c (fx+ next 1))]
                 ;; rotl by 1
                 [rh (fxlogand (fxlogior (sll32 ch 1) (fxsrl cl 31)) mask32)]
                 [rl (fxlogand (fxlogior (sll32 cl 1) (fxsrl ch 31)) mask32)])
            (vector-set! d x2
              (fxlogand (fxlogxor (vector-ref c prev) rh) mask32))
            (vector-set! d (fx+ x2 1)
              (fxlogand (fxlogxor (vector-ref c (fx+ prev 1)) rl) mask32))))

        ;; θ: apply d to all lanes
        (do ([i 0 (fx+ i 1)])
            ((fx= i 25))
          (let* ([i2 (fx* i 2)]
                 [x2 (fx* (fxmod i 5) 2)])
            (vector-set! s i2
              (fxlogand (fxlogxor (vector-ref s i2) (vector-ref d x2)) mask32))
            (vector-set! s (fx+ i2 1)
              (fxlogand (fxlogxor (vector-ref s (fx+ i2 1)) (vector-ref d (fx+ x2 1))) mask32))))

        ;; ── ρ + π ──────────────────────────────────────────────────
        (do ([i 0 (fx+ i 1)])
            ((fx= i 25))
          (let* ([src (vector-ref pi-lanes i)]
                 [src2 (fx* src 2)]
                 [sh (vector-ref s src2)]
                 [sl (vector-ref s (fx+ src2 1))]
                 [r (vector-ref rho-offsets src)]
                 [i2 (fx* i 2)])
            (cond
              [(fx= r 0)
               (vector-set! b i2 sh)
               (vector-set! b (fx+ i2 1) sl)]
              [(fx= r 32)
               (vector-set! b i2 sl)
               (vector-set! b (fx+ i2 1) sh)]
              [(fx< r 32)
               (vector-set! b i2
                 (fxlogand (fxlogior (sll32 sh r) (fxsrl sl (fx- 32 r))) mask32))
               (vector-set! b (fx+ i2 1)
                 (fxlogand (fxlogior (sll32 sl r) (fxsrl sh (fx- 32 r))) mask32))]
              [else  ;; r > 32
               (let ([r2 (fx- r 32)])
                 (vector-set! b i2
                   (fxlogand (fxlogior (sll32 sl r2) (fxsrl sh (fx- 32 r2))) mask32))
                 (vector-set! b (fx+ i2 1)
                   (fxlogand (fxlogior (sll32 sh r2) (fxsrl sl (fx- 32 r2))) mask32)))])))

        ;; ── χ ──────────────────────────────────────────────────────
        (do ([y 0 (fx+ y 5)])
            ((fx= y 25))
          (do ([x 0 (fx+ x 1)])
              ((fx= x 5))
            (let* ([i2 (fx* (fx+ y x) 2)]
                   [j2 (fx* (fx+ y (fxmod (fx+ x 1) 5)) 2)]
                   [k2 (fx* (fx+ y (fxmod (fx+ x 2) 5)) 2)])
              (vector-set! s i2
                (fxlogand
                  (fxlogxor (vector-ref b i2)
                    (fxlogand (fxlogxor (vector-ref b j2) mask32)
                              (vector-ref b k2)))
                  mask32))
              (vector-set! s (fx+ i2 1)
                (fxlogand
                  (fxlogxor (vector-ref b (fx+ i2 1))
                    (fxlogand (fxlogxor (vector-ref b (fx+ j2 1)) mask32)
                              (vector-ref b (fx+ k2 1))))
                  mask32)))))

        ;; ── ι ──────────────────────────────────────────────────────
        (vector-set! s 0
          (fxlogand (fxlogxor (vector-ref s 0) (vector-ref rc-hi round)) mask32))
        (vector-set! s 1
          (fxlogand (fxlogxor (vector-ref s 1) (vector-ref rc-lo round)) mask32)))))

  ;; ── Byte ↔ hi/lo helpers ──────────────────────────────────────────────

  (define (bytes-to-hi bv offset)
    (fxlogior
      (bytevector-u8-ref bv (fx+ offset 4))
      (fxlogior (sll32 (bytevector-u8-ref bv (fx+ offset 5)) 8)
        (fxlogior (sll32 (bytevector-u8-ref bv (fx+ offset 6)) 16)
                  (sll32 (bytevector-u8-ref bv (fx+ offset 7)) 24)))))

  (define (bytes-to-lo bv offset)
    (fxlogior
      (bytevector-u8-ref bv offset)
      (fxlogior (sll32 (bytevector-u8-ref bv (fx+ offset 1)) 8)
        (fxlogior (sll32 (bytevector-u8-ref bv (fx+ offset 2)) 16)
                  (sll32 (bytevector-u8-ref bv (fx+ offset 3)) 24)))))

  ;; ── Sponge ─────────────────────────────────────────────────────────────

  (define spongeOptimized
    (lambda (rate-bytes)
      (lambda (suffix-byte)
        (lambda (output-bytes)
          (lambda (message-fv)
            (let* ([msg-len (flexvector-length message-fv)]
                   [msg (make-bytevector msg-len)]
                   [_ (do ([i 0 (fx+ i 1)])
                          ((fx= i msg-len))
                        (bytevector-u8-set! msg i (flexvector-ref message-fv i)))]
                   [q (fx- rate-bytes (fxmod msg-len rate-bytes))]
                   [padded-len (fx+ msg-len q)]
                   [padded (make-bytevector padded-len 0)]
                   [_ (bytevector-copy! msg 0 padded 0 msg-len)]
                   [_ (if (fx= q 1)
                          (bytevector-u8-set! padded msg-len
                            (fxlogior suffix-byte #x80))
                          (begin
                            (bytevector-u8-set! padded msg-len suffix-byte)
                            (bytevector-u8-set! padded (fx- padded-len 1) #x80)))]
                   [s (make-vector 50 0)]
                   [num-lanes (fxdiv rate-bytes 8)]
                   [num-blocks (fxdiv padded-len rate-bytes)])

              ;; Absorb
              (do ([blk 0 (fx+ blk 1)])
                  ((fx= blk num-blocks))
                (let ([off (fx* blk rate-bytes)])
                  (do ([lane 0 (fx+ lane 1)])
                      ((fx= lane num-lanes))
                    (let* ([byte-off (fx+ off (fx* lane 8))]
                           [lane2 (fx* lane 2)])
                      (vector-set! s lane2
                        (fxlogand
                          (fxlogxor (vector-ref s lane2)
                                    (bytes-to-hi padded byte-off))
                          mask32))
                      (vector-set! s (fx+ lane2 1)
                        (fxlogand
                          (fxlogxor (vector-ref s (fx+ lane2 1))
                                    (bytes-to-lo padded byte-off))
                          mask32)))))
                (keccak-f! s))

              ;; Squeeze
              (let ([out-bv (make-bytevector output-bytes)])
                (let loop ([pos 0])
                  (when (fx< pos output-bytes)
                    (do ([lane 0 (fx+ lane 1)])
                        ((or (fx= lane num-lanes)
                             (fx>= (fx+ pos (fx* lane 8)) output-bytes)))
                      (let* ([base (fx+ pos (fx* lane 8))]
                             [lane2 (fx* lane 2)]
                             [hi (vector-ref s lane2)]
                             [lo (vector-ref s (fx+ lane2 1))])
                        ;; Write lo bytes (0-3)
                        (do ([byte-idx 0 (fx+ byte-idx 1)])
                            ((or (fx= byte-idx 4) (fx>= (fx+ base byte-idx) output-bytes)))
                          (bytevector-u8-set! out-bv (fx+ base byte-idx)
                            (fxlogand (fxsrl lo (fx* byte-idx 8)) #xFF)))
                        ;; Write hi bytes (4-7)
                        (do ([byte-idx 0 (fx+ byte-idx 1)])
                            ((or (fx= byte-idx 4) (fx>= (fx+ base (fx+ byte-idx 4)) output-bytes)))
                          (bytevector-u8-set! out-bv (fx+ base (fx+ byte-idx 4))
                            (fxlogand (fxsrl hi (fx* byte-idx 8)) #xFF)))))
                    (let ([next-pos (fx+ pos rate-bytes)])
                      (when (fx< next-pos output-bytes)
                        (keccak-f! s))
                      (loop next-pos))))

                (let ([result (make-flexvector output-bytes)])
                  (do ([i 0 (fx+ i 1)])
                      ((fx= i output-bytes) result)
                    (flexvector-set! result i
                      (bytevector-u8-ref out-bv i)))))))))))

  ;; ── keccakF1600 wrapper ────────────────────────────────────────────────

  (define keccakF1600Optimized
    (lambda (state-fv)
      (let ([s (make-vector 50)])
        (do ([i 0 (fx+ i 1)])
            ((fx= i 25))
          (let* ([w (flexvector-ref state-fv i)]
                 [i2 (fx* i 2)])
            (vector-set! s i2 (fxlogand (ash w -32) mask32))
            (vector-set! s (fx+ i2 1) (fxlogand w mask32))))
        (keccak-f! s)
        (let ([result (make-flexvector 25)])
          (do ([i 0 (fx+ i 1)])
              ((fx= i 25) result)
            (let ([i2 (fx* i 2)])
              (flexvector-set! result i
                (logior (ash (vector-ref s i2) 32)
                        (vector-ref s (fx+ i2 1))))))))))

) ;; end library