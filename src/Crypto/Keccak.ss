(optimize-level 3)

(library (Crypto.Keccak foreign)
  (export roundConstants orInt spongeOptimized keccakF1600Optimized)
  (import (chezscheme) (srfi :214))

  ;; 32-bit left shift, fully fixnum. Pre-masks input so fxsll never overflows.
  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (fxsll (fxlogand x (fxsrl #xFFFFFFFF n)) n)]))

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

  (define orInt (lambda (a) (lambda (b) (logior a b))))

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

  ;; ── Keccak-f[1600]: fully unrolled, fixnum-only ───────────────────────
  ;; s: mutable vector(50). s[2i]=hi32, s[2i+1]=lo32 for lane i.
  ;; No inner loops. No scratch vectors. All intermediates are locals.

  (define (keccak-f! s)
    (do ([round 0 (fx+ round 1)])
        ((fx= round 24))

      ;; ═══ θ: column parities + d values ═══
      (let* (
             [c0h (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 0) (vector-ref s 10)) (vector-ref s 20)) (vector-ref s 30)) (vector-ref s 40))]
             [c0l (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 1) (vector-ref s 11)) (vector-ref s 21)) (vector-ref s 31)) (vector-ref s 41))]
             [c1h (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 2) (vector-ref s 12)) (vector-ref s 22)) (vector-ref s 32)) (vector-ref s 42))]
             [c1l (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 3) (vector-ref s 13)) (vector-ref s 23)) (vector-ref s 33)) (vector-ref s 43))]
             [c2h (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 4) (vector-ref s 14)) (vector-ref s 24)) (vector-ref s 34)) (vector-ref s 44))]
             [c2l (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 5) (vector-ref s 15)) (vector-ref s 25)) (vector-ref s 35)) (vector-ref s 45))]
             [c3h (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 6) (vector-ref s 16)) (vector-ref s 26)) (vector-ref s 36)) (vector-ref s 46))]
             [c3l (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 7) (vector-ref s 17)) (vector-ref s 27)) (vector-ref s 37)) (vector-ref s 47))]
             [c4h (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 8) (vector-ref s 18)) (vector-ref s 28)) (vector-ref s 38)) (vector-ref s 48))]
             [c4l (fxlogxor (fxlogxor (fxlogxor (fxlogxor (vector-ref s 9) (vector-ref s 19)) (vector-ref s 29)) (vector-ref s 39)) (vector-ref s 49))]
             [d0h (fxlogxor c4h (fxlogior (sll32 c1h 1) (fxsrl c1l 31)))]
             [d0l (fxlogxor c4l (fxlogior (sll32 c1l 1) (fxsrl c1h 31)))]
             [d1h (fxlogxor c0h (fxlogior (sll32 c2h 1) (fxsrl c2l 31)))]
             [d1l (fxlogxor c0l (fxlogior (sll32 c2l 1) (fxsrl c2h 31)))]
             [d2h (fxlogxor c1h (fxlogior (sll32 c3h 1) (fxsrl c3l 31)))]
             [d2l (fxlogxor c1l (fxlogior (sll32 c3l 1) (fxsrl c3h 31)))]
             [d3h (fxlogxor c2h (fxlogior (sll32 c4h 1) (fxsrl c4l 31)))]
             [d3l (fxlogxor c2l (fxlogior (sll32 c4l 1) (fxsrl c4h 31)))]
             [d4h (fxlogxor c3h (fxlogior (sll32 c0h 1) (fxsrl c0l 31)))]
             [d4l (fxlogxor c3l (fxlogior (sll32 c0l 1) (fxsrl c0h 31)))]
             )
        ;; Apply θ
        (vector-set! s 0 (fxlogxor (vector-ref s 0) d0h))
        (vector-set! s 1 (fxlogxor (vector-ref s 1) d0l))
        (vector-set! s 2 (fxlogxor (vector-ref s 2) d1h))
        (vector-set! s 3 (fxlogxor (vector-ref s 3) d1l))
        (vector-set! s 4 (fxlogxor (vector-ref s 4) d2h))
        (vector-set! s 5 (fxlogxor (vector-ref s 5) d2l))
        (vector-set! s 6 (fxlogxor (vector-ref s 6) d3h))
        (vector-set! s 7 (fxlogxor (vector-ref s 7) d3l))
        (vector-set! s 8 (fxlogxor (vector-ref s 8) d4h))
        (vector-set! s 9 (fxlogxor (vector-ref s 9) d4l))
        (vector-set! s 10 (fxlogxor (vector-ref s 10) d0h))
        (vector-set! s 11 (fxlogxor (vector-ref s 11) d0l))
        (vector-set! s 12 (fxlogxor (vector-ref s 12) d1h))
        (vector-set! s 13 (fxlogxor (vector-ref s 13) d1l))
        (vector-set! s 14 (fxlogxor (vector-ref s 14) d2h))
        (vector-set! s 15 (fxlogxor (vector-ref s 15) d2l))
        (vector-set! s 16 (fxlogxor (vector-ref s 16) d3h))
        (vector-set! s 17 (fxlogxor (vector-ref s 17) d3l))
        (vector-set! s 18 (fxlogxor (vector-ref s 18) d4h))
        (vector-set! s 19 (fxlogxor (vector-ref s 19) d4l))
        (vector-set! s 20 (fxlogxor (vector-ref s 20) d0h))
        (vector-set! s 21 (fxlogxor (vector-ref s 21) d0l))
        (vector-set! s 22 (fxlogxor (vector-ref s 22) d1h))
        (vector-set! s 23 (fxlogxor (vector-ref s 23) d1l))
        (vector-set! s 24 (fxlogxor (vector-ref s 24) d2h))
        (vector-set! s 25 (fxlogxor (vector-ref s 25) d2l))
        (vector-set! s 26 (fxlogxor (vector-ref s 26) d3h))
        (vector-set! s 27 (fxlogxor (vector-ref s 27) d3l))
        (vector-set! s 28 (fxlogxor (vector-ref s 28) d4h))
        (vector-set! s 29 (fxlogxor (vector-ref s 29) d4l))
        (vector-set! s 30 (fxlogxor (vector-ref s 30) d0h))
        (vector-set! s 31 (fxlogxor (vector-ref s 31) d0l))
        (vector-set! s 32 (fxlogxor (vector-ref s 32) d1h))
        (vector-set! s 33 (fxlogxor (vector-ref s 33) d1l))
        (vector-set! s 34 (fxlogxor (vector-ref s 34) d2h))
        (vector-set! s 35 (fxlogxor (vector-ref s 35) d2l))
        (vector-set! s 36 (fxlogxor (vector-ref s 36) d3h))
        (vector-set! s 37 (fxlogxor (vector-ref s 37) d3l))
        (vector-set! s 38 (fxlogxor (vector-ref s 38) d4h))
        (vector-set! s 39 (fxlogxor (vector-ref s 39) d4l))
        (vector-set! s 40 (fxlogxor (vector-ref s 40) d0h))
        (vector-set! s 41 (fxlogxor (vector-ref s 41) d0l))
        (vector-set! s 42 (fxlogxor (vector-ref s 42) d1h))
        (vector-set! s 43 (fxlogxor (vector-ref s 43) d1l))
        (vector-set! s 44 (fxlogxor (vector-ref s 44) d2h))
        (vector-set! s 45 (fxlogxor (vector-ref s 45) d2l))
        (vector-set! s 46 (fxlogxor (vector-ref s 46) d3h))
        (vector-set! s 47 (fxlogxor (vector-ref s 47) d3l))
        (vector-set! s 48 (fxlogxor (vector-ref s 48) d4h))
        (vector-set! s 49 (fxlogxor (vector-ref s 49) d4l))
        )

      ;; ═══ ρ + π into locals, then χ + ι back to state ═══
      (let* (
             [b0h (vector-ref s 0)]
             [b0l (vector-ref s 1)]
             [b1h (fxlogior (sll32 (vector-ref s 13) 12) (fxsrl (vector-ref s 12) 20))]
             [b1l (fxlogior (sll32 (vector-ref s 12) 12) (fxsrl (vector-ref s 13) 20))]
             [b2h (fxlogior (sll32 (vector-ref s 25) 11) (fxsrl (vector-ref s 24) 21))]
             [b2l (fxlogior (sll32 (vector-ref s 24) 11) (fxsrl (vector-ref s 25) 21))]
             [b3h (fxlogior (sll32 (vector-ref s 36) 21) (fxsrl (vector-ref s 37) 11))]
             [b3l (fxlogior (sll32 (vector-ref s 37) 21) (fxsrl (vector-ref s 36) 11))]
             [b4h (fxlogior (sll32 (vector-ref s 48) 14) (fxsrl (vector-ref s 49) 18))]
             [b4l (fxlogior (sll32 (vector-ref s 49) 14) (fxsrl (vector-ref s 48) 18))]
             [b5h (fxlogior (sll32 (vector-ref s 6) 28) (fxsrl (vector-ref s 7) 4))]
             [b5l (fxlogior (sll32 (vector-ref s 7) 28) (fxsrl (vector-ref s 6) 4))]
             [b6h (fxlogior (sll32 (vector-ref s 18) 20) (fxsrl (vector-ref s 19) 12))]
             [b6l (fxlogior (sll32 (vector-ref s 19) 20) (fxsrl (vector-ref s 18) 12))]
             [b7h (fxlogior (sll32 (vector-ref s 20) 3) (fxsrl (vector-ref s 21) 29))]
             [b7l (fxlogior (sll32 (vector-ref s 21) 3) (fxsrl (vector-ref s 20) 29))]
             [b8h (fxlogior (sll32 (vector-ref s 33) 13) (fxsrl (vector-ref s 32) 19))]
             [b8l (fxlogior (sll32 (vector-ref s 32) 13) (fxsrl (vector-ref s 33) 19))]
             [b9h (fxlogior (sll32 (vector-ref s 45) 29) (fxsrl (vector-ref s 44) 3))]
             [b9l (fxlogior (sll32 (vector-ref s 44) 29) (fxsrl (vector-ref s 45) 3))]
             [b10h (fxlogior (sll32 (vector-ref s 2) 1) (fxsrl (vector-ref s 3) 31))]
             [b10l (fxlogior (sll32 (vector-ref s 3) 1) (fxsrl (vector-ref s 2) 31))]
             [b11h (fxlogior (sll32 (vector-ref s 14) 6) (fxsrl (vector-ref s 15) 26))]
             [b11l (fxlogior (sll32 (vector-ref s 15) 6) (fxsrl (vector-ref s 14) 26))]
             [b12h (fxlogior (sll32 (vector-ref s 26) 25) (fxsrl (vector-ref s 27) 7))]
             [b12l (fxlogior (sll32 (vector-ref s 27) 25) (fxsrl (vector-ref s 26) 7))]
             [b13h (fxlogior (sll32 (vector-ref s 38) 8) (fxsrl (vector-ref s 39) 24))]
             [b13l (fxlogior (sll32 (vector-ref s 39) 8) (fxsrl (vector-ref s 38) 24))]
             [b14h (fxlogior (sll32 (vector-ref s 40) 18) (fxsrl (vector-ref s 41) 14))]
             [b14l (fxlogior (sll32 (vector-ref s 41) 18) (fxsrl (vector-ref s 40) 14))]
             [b15h (fxlogior (sll32 (vector-ref s 8) 27) (fxsrl (vector-ref s 9) 5))]
             [b15l (fxlogior (sll32 (vector-ref s 9) 27) (fxsrl (vector-ref s 8) 5))]
             [b16h (fxlogior (sll32 (vector-ref s 11) 4) (fxsrl (vector-ref s 10) 28))]
             [b16l (fxlogior (sll32 (vector-ref s 10) 4) (fxsrl (vector-ref s 11) 28))]
             [b17h (fxlogior (sll32 (vector-ref s 22) 10) (fxsrl (vector-ref s 23) 22))]
             [b17l (fxlogior (sll32 (vector-ref s 23) 10) (fxsrl (vector-ref s 22) 22))]
             [b18h (fxlogior (sll32 (vector-ref s 34) 15) (fxsrl (vector-ref s 35) 17))]
             [b18l (fxlogior (sll32 (vector-ref s 35) 15) (fxsrl (vector-ref s 34) 17))]
             [b19h (fxlogior (sll32 (vector-ref s 47) 24) (fxsrl (vector-ref s 46) 8))]
             [b19l (fxlogior (sll32 (vector-ref s 46) 24) (fxsrl (vector-ref s 47) 8))]
             [b20h (fxlogior (sll32 (vector-ref s 5) 30) (fxsrl (vector-ref s 4) 2))]
             [b20l (fxlogior (sll32 (vector-ref s 4) 30) (fxsrl (vector-ref s 5) 2))]
             [b21h (fxlogior (sll32 (vector-ref s 17) 23) (fxsrl (vector-ref s 16) 9))]
             [b21l (fxlogior (sll32 (vector-ref s 16) 23) (fxsrl (vector-ref s 17) 9))]
             [b22h (fxlogior (sll32 (vector-ref s 29) 7) (fxsrl (vector-ref s 28) 25))]
             [b22l (fxlogior (sll32 (vector-ref s 28) 7) (fxsrl (vector-ref s 29) 25))]
             [b23h (fxlogior (sll32 (vector-ref s 31) 9) (fxsrl (vector-ref s 30) 23))]
             [b23l (fxlogior (sll32 (vector-ref s 30) 9) (fxsrl (vector-ref s 31) 23))]
             [b24h (fxlogior (sll32 (vector-ref s 42) 2) (fxsrl (vector-ref s 43) 30))]
             [b24l (fxlogior (sll32 (vector-ref s 43) 2) (fxsrl (vector-ref s 42) 30))]
             )
        ;; χ + ι
        (vector-set! s 0 (fxlogxor (fxlogxor b0h (fxlogand (fxlogxor b1h #xFFFFFFFF) b2h)) (vector-ref rc-hi round)))
        (vector-set! s 1 (fxlogxor (fxlogxor b0l (fxlogand (fxlogxor b1l #xFFFFFFFF) b2l)) (vector-ref rc-lo round)))
        (vector-set! s 2 (fxlogxor b1h (fxlogand (fxlogxor b2h #xFFFFFFFF) b3h)))
        (vector-set! s 3 (fxlogxor b1l (fxlogand (fxlogxor b2l #xFFFFFFFF) b3l)))
        (vector-set! s 4 (fxlogxor b2h (fxlogand (fxlogxor b3h #xFFFFFFFF) b4h)))
        (vector-set! s 5 (fxlogxor b2l (fxlogand (fxlogxor b3l #xFFFFFFFF) b4l)))
        (vector-set! s 6 (fxlogxor b3h (fxlogand (fxlogxor b4h #xFFFFFFFF) b0h)))
        (vector-set! s 7 (fxlogxor b3l (fxlogand (fxlogxor b4l #xFFFFFFFF) b0l)))
        (vector-set! s 8 (fxlogxor b4h (fxlogand (fxlogxor b0h #xFFFFFFFF) b1h)))
        (vector-set! s 9 (fxlogxor b4l (fxlogand (fxlogxor b0l #xFFFFFFFF) b1l)))
        (vector-set! s 10 (fxlogxor b5h (fxlogand (fxlogxor b6h #xFFFFFFFF) b7h)))
        (vector-set! s 11 (fxlogxor b5l (fxlogand (fxlogxor b6l #xFFFFFFFF) b7l)))
        (vector-set! s 12 (fxlogxor b6h (fxlogand (fxlogxor b7h #xFFFFFFFF) b8h)))
        (vector-set! s 13 (fxlogxor b6l (fxlogand (fxlogxor b7l #xFFFFFFFF) b8l)))
        (vector-set! s 14 (fxlogxor b7h (fxlogand (fxlogxor b8h #xFFFFFFFF) b9h)))
        (vector-set! s 15 (fxlogxor b7l (fxlogand (fxlogxor b8l #xFFFFFFFF) b9l)))
        (vector-set! s 16 (fxlogxor b8h (fxlogand (fxlogxor b9h #xFFFFFFFF) b5h)))
        (vector-set! s 17 (fxlogxor b8l (fxlogand (fxlogxor b9l #xFFFFFFFF) b5l)))
        (vector-set! s 18 (fxlogxor b9h (fxlogand (fxlogxor b5h #xFFFFFFFF) b6h)))
        (vector-set! s 19 (fxlogxor b9l (fxlogand (fxlogxor b5l #xFFFFFFFF) b6l)))
        (vector-set! s 20 (fxlogxor b10h (fxlogand (fxlogxor b11h #xFFFFFFFF) b12h)))
        (vector-set! s 21 (fxlogxor b10l (fxlogand (fxlogxor b11l #xFFFFFFFF) b12l)))
        (vector-set! s 22 (fxlogxor b11h (fxlogand (fxlogxor b12h #xFFFFFFFF) b13h)))
        (vector-set! s 23 (fxlogxor b11l (fxlogand (fxlogxor b12l #xFFFFFFFF) b13l)))
        (vector-set! s 24 (fxlogxor b12h (fxlogand (fxlogxor b13h #xFFFFFFFF) b14h)))
        (vector-set! s 25 (fxlogxor b12l (fxlogand (fxlogxor b13l #xFFFFFFFF) b14l)))
        (vector-set! s 26 (fxlogxor b13h (fxlogand (fxlogxor b14h #xFFFFFFFF) b10h)))
        (vector-set! s 27 (fxlogxor b13l (fxlogand (fxlogxor b14l #xFFFFFFFF) b10l)))
        (vector-set! s 28 (fxlogxor b14h (fxlogand (fxlogxor b10h #xFFFFFFFF) b11h)))
        (vector-set! s 29 (fxlogxor b14l (fxlogand (fxlogxor b10l #xFFFFFFFF) b11l)))
        (vector-set! s 30 (fxlogxor b15h (fxlogand (fxlogxor b16h #xFFFFFFFF) b17h)))
        (vector-set! s 31 (fxlogxor b15l (fxlogand (fxlogxor b16l #xFFFFFFFF) b17l)))
        (vector-set! s 32 (fxlogxor b16h (fxlogand (fxlogxor b17h #xFFFFFFFF) b18h)))
        (vector-set! s 33 (fxlogxor b16l (fxlogand (fxlogxor b17l #xFFFFFFFF) b18l)))
        (vector-set! s 34 (fxlogxor b17h (fxlogand (fxlogxor b18h #xFFFFFFFF) b19h)))
        (vector-set! s 35 (fxlogxor b17l (fxlogand (fxlogxor b18l #xFFFFFFFF) b19l)))
        (vector-set! s 36 (fxlogxor b18h (fxlogand (fxlogxor b19h #xFFFFFFFF) b15h)))
        (vector-set! s 37 (fxlogxor b18l (fxlogand (fxlogxor b19l #xFFFFFFFF) b15l)))
        (vector-set! s 38 (fxlogxor b19h (fxlogand (fxlogxor b15h #xFFFFFFFF) b16h)))
        (vector-set! s 39 (fxlogxor b19l (fxlogand (fxlogxor b15l #xFFFFFFFF) b16l)))
        (vector-set! s 40 (fxlogxor b20h (fxlogand (fxlogxor b21h #xFFFFFFFF) b22h)))
        (vector-set! s 41 (fxlogxor b20l (fxlogand (fxlogxor b21l #xFFFFFFFF) b22l)))
        (vector-set! s 42 (fxlogxor b21h (fxlogand (fxlogxor b22h #xFFFFFFFF) b23h)))
        (vector-set! s 43 (fxlogxor b21l (fxlogand (fxlogxor b22l #xFFFFFFFF) b23l)))
        (vector-set! s 44 (fxlogxor b22h (fxlogand (fxlogxor b23h #xFFFFFFFF) b24h)))
        (vector-set! s 45 (fxlogxor b22l (fxlogand (fxlogxor b23l #xFFFFFFFF) b24l)))
        (vector-set! s 46 (fxlogxor b23h (fxlogand (fxlogxor b24h #xFFFFFFFF) b20h)))
        (vector-set! s 47 (fxlogxor b23l (fxlogand (fxlogxor b24l #xFFFFFFFF) b20l)))
        (vector-set! s 48 (fxlogxor b24h (fxlogand (fxlogxor b20h #xFFFFFFFF) b21h)))
        (vector-set! s 49 (fxlogxor b24l (fxlogand (fxlogxor b20l #xFFFFFFFF) b21l)))
        )
      ))

  ;; ── Byte helpers ───────────────────────────────────────────────────────

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
                        (fxlogxor (vector-ref s lane2)
                                  (bytes-to-hi padded byte-off)))
                      (vector-set! s (fx+ lane2 1)
                        (fxlogxor (vector-ref s (fx+ lane2 1))
                                  (bytes-to-lo padded byte-off))))))
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
            (vector-set! s i2 (fxlogand (ash w -32) #xFFFFFFFF))
            (vector-set! s (fx+ i2 1) (fxlogand w #xFFFFFFFF))))
        (keccak-f! s)
        (let ([result (make-flexvector 25)])
          (do ([i 0 (fx+ i 1)])
              ((fx= i 25) result)
            (let ([i2 (fx* i 2)])
              (flexvector-set! result i
                (logior (ash (vector-ref s i2) 32)
                        (vector-ref s (fx+ i2 1))))))))))

) ;; end library