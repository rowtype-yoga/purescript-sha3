;;; Crypto.Word64 — Chez Scheme FFI
;;;
;;; Native 64-bit bitwise operations for Keccak-f[1600].
;;; On a 64-bit Chez Scheme, fixnums cover [-2^60, 2^60-1].
;;; Full 64-bit unsigned values (up to 2^64-1) may be bignums,
;;; but Chez handles the promotion transparently and the bitwise
;;; ops (logand, logior, logxor, lognot, ash) work on arbitrary
;;; precision integers.

(library (Crypto.Word64 foreign)
  (export w64xor w64and w64or w64complement w64rotL
          _assembleBytesLE w64toBytesLE)
  (import (chezscheme)
          (srfi :214))

  ;; 64-bit mask: all bits set in [0..63]
  (define mask64 #xFFFFFFFFFFFFFFFF)

  ;; XOR — result of two 64-bit values XOR'd is still ≤64 bits,
  ;; but we mask defensively.
  (define w64xor
    (lambda (a)
      (lambda (b)
        (logand (logxor a b) mask64))))

  ;; AND — always shrinks or stays same size.
  (define w64and
    (lambda (a)
      (lambda (b)
        (logand a b))))

  ;; OR — mask to 64 bits.
  (define w64or
    (lambda (a)
      (lambda (b)
        (logand (logior a b) mask64))))

  ;; Complement — mask to 64 bits (lognot produces negative for
  ;; nonnegative input in two's complement interpretation).
  (define w64complement
    (lambda (a)
      (logand (lognot a) mask64)))

  ;; Left-rotate by n positions within a 64-bit window.
  ;; rotL(x, n) = ((x << n) | (x >>> (64-n))) & mask64
  (define w64rotL
    (lambda (x)
      (lambda (n)
        (if (= n 0)
            x
            (logand
              (logior (ash x n)
                      (ash x (- n 64)))
              mask64)))))

  ;; Assemble 8 little-endian bytes into one 64-bit word.
  ;; b0 is the least significant byte.
  (define _assembleBytesLE
    (lambda (b0)
      (lambda (b1)
        (lambda (b2)
          (lambda (b3)
            (lambda (b4)
              (lambda (b5)
                (lambda (b6)
                  (lambda (b7)
                    (logior b0
                      (logior (ash b1 8)
                        (logior (ash b2 16)
                          (logior (ash b3 24)
                            (logior (ash b4 32)
                              (logior (ash b5 40)
                                (logior (ash b6 48)
                                  (ash b7 56)))))))))))))))))

  ;; Decompose a 64-bit word into a flexvector of 8 bytes,
  ;; little-endian order.
  (define w64toBytesLE
    (lambda (w)
      (list->flexvector
        (list
          (logand w #xFF)
          (logand (ash w -8) #xFF)
          (logand (ash w -16) #xFF)
          (logand (ash w -24) #xFF)
          (logand (ash w -32) #xFF)
          (logand (ash w -40) #xFF)
          (logand (ash w -48) #xFF)
          (logand (ash w -56) #xFF)))))

) ;; end library