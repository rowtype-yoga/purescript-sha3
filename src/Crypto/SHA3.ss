;;; Crypto.SHA3 — Chez Scheme FFI

(library (Crypto.SHA3 foreign)
  (export stringToUtf8 bytesToHex hexToBytes_)
  (import (chezscheme)
          (purescm pstring)
          (srfi :214))

  ;; Convert a PureScript String (pstring) to a flexvector of UTF-8 bytes.
  (define stringToUtf8
    (lambda (pstr)
      (let* ([str (pstring->string pstr)]
             [bv (string->utf8 str)]
             [len (bytevector-length bv)])
        (let ([fv (make-flexvector len)])
          (let loop ([i 0])
            (if (= i len)
                fv
                (begin
                  (flexvector-set! fv i (bytevector-u8-ref bv i))
                  (loop (+ i 1)))))))))

  ;; Encode a flexvector of byte values as a lowercase hex string.
  (define bytesToHex
    (lambda (arr)
      (let* ([len (flexvector-length arr)]
             [hex-chars "0123456789abcdef"])
        (let loop ([i 0] [acc '()])
          (if (= i len)
              (string->pstring (apply string-append (reverse acc)))
              (let ([b (flexvector-ref arr i)])
                (loop (+ i 1)
                      (cons (string
                              (string-ref hex-chars (ash b -4))
                              (string-ref hex-chars (logand b #xF)))
                            acc))))))))

  ;; Decode a hex string to a flexvector of bytes, returning (Just arr) or Nothing.
  (define hexToBytes_
    (lambda (just)
      (lambda (nothing)
        (lambda (pstr)
          (let* ([str (pstring->string pstr)]
                 [len (string-length str)])
            (if (or (odd? len)
                    (not (hex-string? str)))
                nothing
                (just
                 (let* ([out-len (div len 2)]
                        [fv (make-flexvector out-len)])
                   (let loop ([i 0] [j 0])
                     (if (= i len)
                         fv
                         (begin
                           (flexvector-set! fv j
                             (+ (* (hex-val (string-ref str i)) 16)
                                (hex-val (string-ref str (+ i 1)))))
                           (loop (+ i 2) (+ j 1)))))))))))))

  (define (hex-string? str)
    (let ([len (string-length str)])
      (let loop ([i 0])
        (or (= i len)
            (and (hex-char? (string-ref str i))
                 (loop (+ i 1)))))))

  (define (hex-char? c)
    (or (char<=? #\0 c #\9)
        (char<=? #\a c #\f)
        (char<=? #\A c #\F)))

  (define (hex-val c)
    (cond
      [(char<=? #\0 c #\9) (- (char->integer c) (char->integer #\0))]
      [(char<=? #\a c #\f) (+ 10 (- (char->integer c) (char->integer #\a)))]
      [(char<=? #\A c #\F) (+ 10 (- (char->integer c) (char->integer #\A)))]))
)