;;; Crypto.Keccak — Optimized Chez Scheme FFI (fully fixnum, optimize-level 3)

(optimize-level 3)

(library (Crypto.Keccak foreign)
  (export roundConstants orInt spongeOptimized keccakF1600Optimized)
  (import (chezscheme)
          (srfi :214))

  (define mask32 #xFFFFFFFF)

  ;; ── Safe 32-bit left shift (all fixnum, zero allocation) ───────────────
  ;; Masks input to (32-n) bits first so fxsll can never exceed fixnum range.
  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (fxlogand (fxsll (fxlogand x (fxsrl mask32 n)) n) mask32)]))

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
    (lambda (a) (lambda (b) (logior a b))))

  ;; ── Round constants hi/lo ──────────────────────────────────────────────

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

  ;; ── ρ offsets & π lanes ────────────────────────────────────────────────

  (define rho-offsets
    '#( 0  1 62 28 27  36 44  6 55 20
        3 10 43 25 39  41 45 15 21  8
       18  2 61 56 14))

  (define pi-lanes
    '#(0 10 20 5 15  16 1 11 21 6  7 17 2 12 22  23 8 18 3 13  14 24 9 19 4))

  ;; ── Precomputed mod tables (eliminates fxmod in loops) ─────────────────

  ;; (x+4) mod 5 for x in [0..4]
  (define theta-prev '#(4 0 1 2 3))
  ;; (x+1) mod 5 for x in [0..4]
  (define theta-next '#(1 2 3 4 0))
  ;; i mod 5 for i in [0..24]
  (define mod5-table
    '#(0 1 2 3 4  0 1 2 3 4  0 1 2 3 4  0 1 2 3 4  0 1 2 3 4))
  ;; (x+1) mod 5 for chi, by y-offset and x
  (define chi-j  ;; (y*5 + ((x+1)%5)) for each (y,x)
    '#( 1  2  3  4  0
        6  7  8  9  5
       11 12 13 14 10
       16 17 18 19 15
       21 22 23 24 20))
  (define chi-k  ;; (y*5 + ((x+2)%5)) for each (y,x)
    '#( 2  3  4  0  1
        7  8  9  5  6
       12 13 14 10 11
       17 18 19 15 16
       22 23 24 20 21))

  ;; ── Rotation helper ────────────────────────────────────────────────────
  ;; Rotates a hi/lo pair left by r bits, writing results to b at i2.
  (define-syntax rotate-lane!
    (syntax-rules ()
      [(_ b i2 sh sl r)
       (cond
         [(fx= r 0)
          (vector-set! b i2 sh)
          (vector-set! b (fx+ i2 1) sl)]
         [(fx= r 32)
          (vector-set! b i2 sl)
          (vector-set! b (fx+ i2 1) sh)]
         [(fx< r 32)
          (vector-set! b i2
            (fxlogior (sll32 sh r) (fxsrl sl (fx- 32 r))))
          (vector-set! b (fx+ i2 1)
            (fxlogior (sll32 sl r) (fxsrl sh (fx- 32 r))))]
         [else
          (let ([r2 (fx- r 32)])
            (vector-set! b i2
              (fxlogior (sll32 sl r2) (fxsrl sh (fx- 32 r2))))
            (vector-set! b (fx+ i2 1)
              (fxlogior (sll32 sh r2) (fxsrl sl (fx- 32 r2)))))])]))

  ;; ── Keccak-f[1600] ────────────────────────────────────────────────────
  ;; s: mutable vector(50), layout: s[2i]=hi32, s[2i+1]=lo32 for lane i.

  (define (keccak-f! s)
    (let ([c (make-vector 10)]
          [d (make-vector 10)]
          [b (make-vector 50)])
      (do ([round 0 (fx+ round 1)])
          ((fx= round 24))

        ;; ── θ: column parities (unrolled) ──────────────────────────
        (let-syntax ([col-parity!
                      (syntax-rules ()
                        [(_ x)
                         (let ([x2 (fx* x 2)])
                           (vector-set! c x2
                             (fxlogand
                               (fxlogxor
                                 (fxlogxor (vector-ref s x2)
                                           (vector-ref s (fx+ x2 10)))
                                 (fxlogxor (vector-ref s (fx+ x2 20))
                                   (fxlogxor (vector-ref s (fx+ x2 30))
                                             (vector-ref s (fx+ x2 40)))))
                               mask32))
                           (let ([x2+1 (fx+ x2 1)])
                             (vector-set! c x2+1
                               (fxlogand
                                 (fxlogxor
                                   (fxlogxor (vector-ref s x2+1)
                                             (vector-ref s (fx+ x2+1 10)))
                                   (fxlogxor (vector-ref s (fx+ x2+1 20))
                                     (fxlogxor (vector-ref s (fx+ x2+1 30))
                                               (vector-ref s (fx+ x2+1 40)))))
                                 mask32))))])])
          (col-parity! 0) (col-parity! 1) (col-parity! 2)
          (col-parity! 3) (col-parity! 4))

        ;; θ: d[x] = c[(x+4)%5] XOR rotl(c[(x+1)%5], 1)
        (do ([x 0 (fx+ x 1)])
            ((fx= x 5))
          (let* ([x2 (fx* x 2)]
                 [prev (fx* (vector-ref theta-prev x) 2)]
                 [next (fx* (vector-ref theta-next x) 2)]
                 [ch (vector-ref c next)]
                 [cl (vector-ref c (fx+ next 1))]
                 [rh (fxlogior (sll32 ch 1) (fxsrl cl 31))]
                 [rl (fxlogior (sll32 cl 1) (fxsrl ch 31))])
            (vector-set! d x2
              (fxlogand (fxlogxor (vector-ref c prev) rh) mask32))
            (vector-set! d (fx+ x2 1)
              (fxlogand (fxlogxor (vector-ref c (fx+ prev 1)) rl) mask32))))

        ;; θ: apply d
        (do ([i 0 (fx+ i 1)])
            ((fx= i 25))
          (let* ([i2 (fx* i 2)]
                 [x2 (fx* (vector-ref mod5-table i) 2)])
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
            (rotate-lane! b i2 sh sl r)))

        ;; ── χ (using precomputed index tables) ─────────────────────
        (do ([i 0 (fx+ i 1)])
            ((fx= i 25))
          (let* ([i2 (fx* i 2)]
                 [j2 (fx* (vector-ref chi-j i) 2)]
                 [k2 (fx* (vector-ref chi-k i) 2)])
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
                mask32))))

        ;; ── ι ──────────────────────────────────────────────────────
        (vector-set! s 0
          (fxlogand (fxlogxor (vector-ref s 0) (vector-ref rc-hi round)) mask32))
        (vector-set! s 1
          (fxlogand (fxlogxor (vector-ref s 1) (vector-ref rc-lo round)) mask32)))))

  ;; ── Byte ↔ hi/lo ──────────────────────────────────────────────────────

  (define (bytes-to-hi bv offset)
    (fxlogior
      (bytevector-u8-ref bv (fx+ offset 4))
      (fxlogior (fxsll (bytevector-u8-ref bv (fx+ offset 5)) 8)
        (fxlogior (fxsll (bytevector-u8-ref bv (fx+ offset 6)) 16)
                  (fxsll (bytevector-u8-ref bv (fx+ offset 7)) 24)))))

  (define (bytes-to-lo bv offset)
    (fxlogior
      (bytevector-u8-ref bv offset)
      (fxlogior (fxsll (bytevector-u8-ref bv (fx+ offset 1)) 8)
        (fxlogior (fxsll (bytevector-u8-ref bv (fx+ offset 2)) 16)
                  (fxsll (bytevector-u8-ref bv (fx+ offset 3)) 24)))))

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
                        (do ([byte-idx 0 (fx+ byte-idx 1)])
                            ((or (fx= byte-idx 4) (fx>= (fx+ base byte-idx) output-bytes)))
                          (bytevector-u8-set! out-bv (fx+ base byte-idx)
                            (fxlogand (fxsrl lo (fx* byte-idx 8)) #xFF)))
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