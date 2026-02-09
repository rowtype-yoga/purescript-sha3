# Understanding SHA-3: A Line-by-Line Walkthrough of Keccak.purs

## The Big Picture First

SHA-3 is a cryptographic hash function. You give it any data — a password, a file, a single byte — and it gives you back a fixed-size fingerprint (called a **digest**). Two important properties:

1. The same input always produces the same digest.
1. It’s practically impossible to reverse-engineer the input from the digest.

SHA-3 is built on an algorithm called **Keccak** (pronounced “ketchak”). The core idea is called the **sponge construction**, and it works in two phases:

- **Absorb**: Feed your input data into a big block of internal state, chunk by chunk, scrambling everything after each chunk.
- **Squeeze**: Read output bytes out of the scrambled state.

The “scrambling” is where all the cryptographic magic happens. It’s a function called **Keccak-f[1600]** — a permutation that takes 1600 bits of state and rearranges them through 24 rounds of five specific operations (θ, ρ, π, χ, ι). These five operations are designed so that after enough rounds, every output bit depends on every input bit in a way that’s impossible to untangle.

That’s the full algorithm. Everything in `Keccak.purs` exists to implement those two ideas: the sponge (absorb/squeeze) and the permutation (the five step mappings repeated 24 times).

-----

## The State: A 5×5×64 Cube of Bits

The spec describes the state as a three-dimensional array of 1600 bits, organized as a 5×5 grid of **lanes**, where each lane is 64 bits long:

```
     x=0   x=1   x=2   x=3   x=4
y=0  [lane] [lane] [lane] [lane] [lane]
y=1  [lane] [lane] [lane] [lane] [lane]
y=2  [lane] [lane] [lane] [lane] [lane]
y=3  [lane] [lane] [lane] [lane] [lane]
y=4  [lane] [lane] [lane] [lane] [lane]
```

That’s 25 lanes × 64 bits = 1600 bits total.

Think of it like a Rubik’s cube made of bits. The five step mappings each twist this cube in a different way — some mix across rows, some rotate within lanes, some shuffle lane positions around.

### Why Lanes? Why Not Just an Array of 1600 Bits?

Performance. Every operation in Keccak works on whole lanes (64-bit chunks) at a time, not individual bits. If we stored 1600 individual bits, every operation would need 1600 array lookups. With 25 lanes, we do 25 lookups and operate on 64 bits at once using fast bitwise operations.

-----

## The 32-bit Problem: Why Lanes Have `hi` and `lo`

```purescript
type Lane = { hi :: Int, lo :: Int }
```

Here’s the catch: PureScript compiles to JavaScript, and JavaScript’s bitwise operators only work on **32-bit integers**. But Keccak lanes are **64 bits** wide. So we split each lane into two halves:

- `lo` holds bits 0–31 (the “low” half)
- `hi` holds bits 32–63 (the “high” half)

Every lane operation (`xorLane`, `andLane`, `complementLane`, `rotL`) does the same thing to both halves. For XOR, AND, and NOT this is straightforward — just apply the operation to each half independently:

```purescript
xorLane a b = { hi: xor a.hi b.hi, lo: xor a.lo b.lo }
andLane a b = { hi: a.hi .&. b.hi, lo: a.lo .&. b.lo }
complementLane a = { hi: complement a.hi, lo: complement a.lo }
```

### Rotation (`rotL`) Is the Tricky One

Rotating a 64-bit value left by `n` means: shift everything left by `n` positions, and whatever falls off the top wraps around to the bottom.

With two 32-bit halves, bits can overflow from `lo` into `hi` and vice versa. There are four cases:

**`n == 0`**: Do nothing.

**`n == 32`**: The halves just swap — what was in `lo` moves to `hi` and vice versa. No bit shifting needed.

**`n < 32`**: Each half shifts left by `n`, but the top `n` bits that would fall off one half need to wrap into the bottom of the other half. That’s what `zshr (32 - n)` does — it captures those overflow bits:

```purescript
{ hi: (lane.hi `shl` n) .|. (lane.lo `zshr` (32 - n))
, lo: (lane.lo `shl` n) .|. (lane.hi `zshr` (32 - n))
}
```

Reading that line: “the new `hi` is the old `hi` shifted left by `n`, combined with the top `n` bits of the old `lo` that overflow into it.”

**`n > 32`**: Same idea but the halves swap first (since we’re rotating more than half the width), then shift by `n - 32`.

`zshr` is **unsigned** right shift (zero-fill). Regular right shift (`shr`) copies the sign bit, which would corrupt our bit patterns. This distinction matters a lot — using `shr` here would be a bug.

-----

## State Access: What `at` Does and Why It Exists

```purescript
at :: State -> Int -> Int -> Lane
at st x y = fromMaybe zeroLane (st !! (x + 5 * y))
```

The state is stored as a flat array of 25 lanes, but the spec describes operations using `(x, y)` coordinates. `at` bridges that gap.

**The formula `x + 5 * y`** converts 2D coordinates to a flat index:

```
(0,0) → 0    (1,0) → 1    (2,0) → 2    (3,0) → 3    (4,0) → 4
(0,1) → 5    (1,1) → 6    (2,1) → 7    (3,1) → 8    (4,1) → 9
(0,2) → 10   (1,2) → 11   (2,2) → 12   (3,2) → 13   (4,2) → 14
...
(0,4) → 20   (1,4) → 21   (2,4) → 22   (3,4) → 23   (4,4) → 24
```

**Why `fromMaybe zeroLane`?** PureScript’s array access (`!!`) returns `Maybe` because the index might be out of bounds. We know our indices are always 0–24, but the type system doesn’t. `fromMaybe zeroLane` says “if the lookup somehow fails, treat it as all zeros.” In practice this never triggers — it’s just satisfying the compiler.

**Why does `at` exist at all?** Without it, every step mapping would have to write `fromMaybe zeroLane (st !! (x + 5 * y))` over and over. The step mappings reference lanes by `(x, y)` coordinates constantly — theta alone does it 30+ times. `at` keeps that readable:

```purescript
-- With `at`:
at st x 0 `xorLane` at st x 1 `xorLane` at st x 2

-- Without `at`:
fromMaybe zeroLane (st !! (x + 5 * 0))
  `xorLane` fromMaybe zeroLane (st !! (x + 5 * 1))
  `xorLane` fromMaybe zeroLane (st !! (x + 5 * 2))
```

### `stateFromFn`: Building a New State

```purescript
stateFromFn :: (Int -> Int -> Lane) -> State
stateFromFn f = do
  y <- A.range 0 4
  x <- A.range 0 4
  pure (f x y)
```

This builds a 25-element array by calling a function for every `(x, y)` pair. The `do` notation here is using the Array monad — it’s a concise way to write a nested loop. It iterates `y` from 0 to 4, and for each `y`, iterates `x` from 0 to 4, producing `f x y` for each combination.

It exists because every step mapping needs to produce a new state where each lane is computed from some formula involving `x` and `y`. Without it, you’d be manually constructing 25-element arrays everywhere.

-----

## Byte ↔ Lane Conversion: Getting Data In and Out

The sponge feeds **bytes** into the state, but the state is made of **lanes** (64-bit values). We need conversion functions.

### `bytesToLane`: 8 Bytes → 1 Lane

```purescript
bytesToLane bytes offset =
  let b i = fromMaybe 0 (bytes !! (offset + i))
  in
    { lo: b 0 .|. (b 1 `shl` 8) .|. (b 2 `shl` 16) .|. (b 3 `shl` 24)
    , hi: b 4 .|. (b 5 `shl` 8) .|. (b 6 `shl` 16) .|. (b 7 `shl` 24)
    }
```

This reads 8 consecutive bytes from the array and packs them into a lane using **little-endian** byte order (the first byte goes in the lowest bits). The `shl 8`, `shl 16`, `shl 24` shift each byte to its correct position within the 32-bit half.

Concrete example: bytes `[0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]` become:

- `lo = 0x01EFCDAB` (bytes 0–3, first byte in lowest position)
- `hi = 0x89674523` (bytes 4–7, same pattern)

### `laneToBytes`: 1 Lane → 8 Bytes

The reverse. Mask off each byte with `.&. 0xFF` and shift right to extract it:

```purescript
[ lane.lo .&. 0xFF              -- byte 0: lowest 8 bits of lo
, (lane.lo `zshr` 8) .&. 0xFF  -- byte 1: next 8 bits of lo
, (lane.lo `zshr` 16) .&. 0xFF -- byte 2: ...
, (lane.lo `zshr` 24) .&. 0xFF -- byte 3: highest 8 bits of lo
, lane.hi .&. 0xFF              -- byte 4: lowest 8 bits of hi
, ...
]
```

### `xorBytesIntoState` and `extractBytes`: Bulk Operations

`xorBytesIntoState` takes a block of input bytes and XORs them into the state, lane by lane. Only the first `rateBytes / 8` lanes get touched — the rest (the “capacity” portion) are left alone. This is core to the sponge: you only feed data into the “rate” portion of the state.

`extractBytes` does the reverse — pulls bytes back out of the rate portion of the state for the squeeze phase.

-----

## The Five Step Mappings: Where the Crypto Happens

Each round of Keccak applies five transformations in sequence: θ → ρ → π → χ → ι. Together, they ensure that after 24 rounds, the state is thoroughly scrambled. Each one serves a specific purpose.

### θ (Theta): Column Parity Mixing

```purescript
theta st =
  let
    c x = at st x 0 `xorLane` at st x 1 `xorLane` at st x 2
           `xorLane` at st x 3 `xorLane` at st x 4

    d x = cAt ((x + 4) `mod` 5) `xorLane` rotL (cAt ((x + 1) `mod` 5)) 1
  in
    stateFromFn (\x y -> at st x y `xorLane` dAt x)
```

**What it does:** For each column (a vertical stack of 5 lanes sharing the same x-coordinate), compute the “parity” — XOR all 5 lanes together. Then XOR each lane with the parities of its two neighboring columns (one to the left, one to the right but rotated by 1 bit).

**Why it matters:** This is the **diffusion** step. It spreads information between columns. After theta, every lane depends on two neighboring columns. This is what makes it impossible to change one bit of input without affecting many bits of output.

**The `mod 5`** wraps around — column 0’s left neighbor is column 4, and column 4’s right neighbor is column 0. The state is a torus (donut shape) in the x-direction.

### ρ (Rho): Lane Rotation

```purescript
rho st =
  A.mapWithIndex
    (\i lane -> rotL lane (fromMaybe 0 (rhoOffsets !! i)))
    st
```

**What it does:** Rotates each lane by a fixed number of bit positions. Lane (0,0) rotates by 0, lane (1,0) by 1, lane (2,0) by 62, etc. The offsets come from a lookup table (`rhoOffsets`) which is defined by the spec.

**Why it matters:** This is **inter-slice diffusion**. Without rho, information would only spread within each 2D slice of the state. Rho moves bits along the z-axis (the depth of each lane), ensuring information from one “layer” of the cube reaches other layers.

**Why are the offsets those specific numbers?** They come from a formula: `(t+1)(t+2)/2 mod 64` for a specific sequence of `(x,y)` pairs defined by the spec. The numbers look arbitrary but are carefully chosen so that after enough rounds, bits reach every position.

### π (Pi): Lane Position Shuffle

```purescript
pi st = stateFromFn (\x y -> at st ((x + 3 * y) `mod` 5) x)
```

**What it does:** Rearranges which lane sits at which `(x, y)` position. The lane that was at position `((x + 3*y) mod 5, x)` moves to position `(x, y)`.

**Why it matters:** Theta mixes columns and rho rotates within lanes, but neither changes which lane is where. Pi scrambles the 2D layout of the grid. Combined with theta, this ensures that information from any single lane eventually reaches all 25 lanes.

**Why `x + 3*y`?** This specific linear transformation over GF(5) (integers mod 5) is chosen because it’s a permutation — every lane ends up in a unique new position, nothing collides.

### χ (Chi): The Non-Linear Step

```purescript
chi st = stateFromFn \x y ->
  at st x y `xorLane`
    (complementLane (at st ((x + 1) `mod` 5) y)
      `andLane` at st ((x + 2) `mod` 5) y)
```

**What it does:** For each lane at `(x, y)`, XOR it with the result of: (NOT the lane at `x+1`) AND (the lane at `x+2`). All within the same row (same `y`).

**Why it matters:** This is the **only non-linear operation** in the entire permutation. Everything else (XOR, rotation, shuffling) is linear — you can describe them with matrices. Chi uses AND, which makes the relationship between input and output bits non-linear. This is what makes SHA-3 cryptographically secure. Without chi, you could solve for the input using linear algebra. With chi, you can’t.

**Reading the formula:** “Take the neighbor one step to the right, flip all its bits, AND it with the neighbor two steps to the right, then XOR the result into the current lane.” It’s a simple formula but it creates complex, unpredictable bit interactions.

### ι (Iota): Round Constant Injection

```purescript
iota ir st =
  let
    rc = fromMaybe zeroLane (roundConstants !! ir)
    lane0 = fromMaybe zeroLane (st !! 0)
  in
    fromMaybe st (A.updateAt 0 (xorLane lane0 rc) st)
```

**What it does:** XORs a fixed constant into lane (0, 0). The constant is different for each of the 24 rounds.

**Why it matters:** Without iota, every round would be identical. Identical rounds create structural symmetry that an attacker could exploit. The round constants break this symmetry — each round behaves slightly differently, preventing “slide attacks” and other symmetry-based cryptanalysis.

**Why only lane (0, 0)?** It seems like modifying just one lane out of 25 would be weak, but remember: theta immediately spreads lane (0, 0)’s changes to all neighboring columns, and then pi shuffles everything around. After a few rounds, the constant has influenced every bit.

### The Round Constants Table

```purescript
roundConstants =
  [ { hi: 0, lo: 1 }                -- Round 0:  0x0000000000000001
  , { hi: 0, lo: 0x8082 }           -- Round 1:  0x0000000000008082
  , { hi: b31, lo: 0x808A }         -- Round 2:  0x800000000000808A
  ...
  ]
```

These 24 constants are derived from a linear feedback shift register (LFSR) — a deterministic sequence that looks random. They’re not arbitrary; they’re computed by Algorithm 5 (the `rc(t)` function) in the spec. We precompute them because computing them on the fly each round would waste time for no benefit.

`b31` is `1 << 31`, which is bit 31 set in a 32-bit integer. In JavaScript’s 32-bit signed arithmetic, this is the sign bit, so it appears as a negative number. That’s fine — bitwise operations work on the underlying bits regardless of sign interpretation.

-----

## The Full Permutation: 24 Rounds

```purescript
round ir = iota ir <<< chi <<< pi <<< rho <<< theta

keccakF1600 st = foldl (\s ir -> round ir s) st (A.range 0 23)
```

One round is: theta, then rho, then pi, then chi, then iota. The `<<<` operator composes functions right-to-left, so `iota ir <<< chi <<< pi <<< rho <<< theta` means “apply theta first, then rho, then pi, then chi, then iota.” This matches the spec exactly: `Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir)`.

`keccakF1600` repeats this 24 times (round indices 0 through 23). After 24 rounds, every bit of the state depends on every other bit in a way that’s computationally irreversible without knowing the original input.

**Why 24?** The number of rounds is `12 + 2l` where `l = log2(w)`. For `w = 64` (lane size), `l = 6`, so `12 + 12 = 24`. More rounds = more security but slower. 24 rounds gives a very large security margin — no known attack comes close to breaking it.

-----

## Padding: Making the Input Fit

```purescript
padMessage suffixByte rateBytes message =
  let
    q = rateBytes - (msgLen `mod` rateBytes)
  in
    if q == 1 then
      message <> [ suffixByte .|. 0x80 ]
    else
      message <> [ suffixByte ] <> A.replicate (q - 2) 0 <> [ 0x80 ]
```

The sponge processes input in blocks of `rateBytes`. If the message isn’t an exact multiple of that block size, we need to pad it. The padding scheme is called **pad10*1**:

- Append a `1` bit
- Append zero or more `0` bits
- Append a final `1` bit
- Such that the total length is now a multiple of `rateBytes`

But we also need **domain separation** — a way to tell SHA-3 hash functions apart from SHAKE XOFs. This is the `suffixByte`:

- `0x06` for SHA-3 hash functions (the bits `01 1` — two domain bits plus the first padding bit)
- `0x1F` for SHAKE XOFs (the bits `1111 1` — four domain bits plus the first padding bit)

The final `0x80` is the closing `1` bit of pad10*1 (bit 7 of the last byte).

**Special case `q == 1`:** If there’s only room for one padding byte, the suffix and the final `1` bit get combined into a single byte: `suffixByte .|. 0x80`.

-----

## The Sponge: Absorb and Squeeze

```purescript
sponge rateBytes suffixByte outputBytes message = ...
```

This is the top-level function that ties everything together.

### Absorb Phase

```purescript
absorb st blockIdx =
  let
    block = A.slice (blockIdx * rateBytes) ((blockIdx + 1) * rateBytes) padded
    xored = xorBytesIntoState block rateBytes st
  in
    keccakF1600 xored

absorbed = foldl absorb emptyState (A.range 0 (numBlocks - 1))
```

1. Start with an empty state (all 1600 bits zero).
1. Take the first `rateBytes` bytes of the padded message.
1. XOR them into the first `rateBytes / 8` lanes of the state. The remaining lanes (the “capacity”) are untouched — they hold internal state that the attacker never sees directly.
1. Run `keccakF1600` to scramble everything.
1. Repeat for each block of the padded message.

**Why XOR?** XOR is reversible (you can undo it), but that’s fine because `keccakF1600` makes the combined operation irreversible. XOR is also fast and doesn’t require any special handling of the existing state — it cleanly mixes new data with whatever was already there.

**Why is the capacity untouched?** This is the core security argument of the sponge construction. The capacity bits act as a “secret” internal state that the input never directly overwrites and the output never directly reveals. The security level is `capacity / 2` bits. For SHA3-256, capacity = 512, so security = 256 bits.

### Squeeze Phase

```purescript
initialSqueeze = { out: extractBytes rateBytes absorbed, st: absorbed }

squeezed = squeezeLoop outputBytes rateBytes initialSqueeze
```

1. Extract the first `rateBytes` bytes from the state. These are the first output bytes.
1. If that’s enough output, stop.
1. Otherwise, run `keccakF1600` again to scramble the state, extract another `rateBytes` bytes, and append them. Repeat until you have enough.

For SHA-3 hash functions (SHA3-256 outputs 32 bytes, rate is 136 bytes), one squeeze is always enough. The squeeze loop only activates for SHAKE XOFs when you request more output than the rate.

-----

## How Everything Connects

Here’s the full call chain when you do `sha3_256 someInput`:

```
sha3_256 someInput
  └─ sponge 136 0x06 32 someInput
       ├─ padMessage 0x06 136 someInput     → padded input (multiple of 136 bytes)
       ├─ for each 136-byte block:
       │    ├─ xorBytesIntoState block 136 state
       │    │    └─ bytesToLane (8 bytes → 1 lane, repeated 17 times)
       │    └─ keccakF1600 state
       │         └─ 24 × round:
       │              ├─ theta  (column parity mixing)
       │              ├─ rho    (lane rotation)
       │              ├─ pi     (lane position shuffle)
       │              ├─ chi    (non-linear row mixing)
       │              └─ iota   (round constant XOR)
       └─ extractBytes 136 state → take first 32 bytes
            └─ laneToBytes (1 lane → 8 bytes, repeated 17 times)
```

For a short message like “abc” (3 bytes), padding brings it to exactly 136 bytes (one block), so there’s one absorb pass and one squeeze pass. For a 200-byte message, padding brings it to 272 bytes (two blocks), so there are two absorb passes — meaning `keccakF1600` runs twice during absorption.

-----

## Summary Table

|Function           |Purpose                             |Why It Exists                                                     |
|-------------------|------------------------------------|------------------------------------------------------------------|
|`zeroLane`         |A lane of all zeros                 |Default/initial value for state lanes                             |
|`xorLane`          |XOR two 64-bit lanes                |Core operation — mixing, absorbing, theta, iota all use XOR       |
|`andLane`          |AND two 64-bit lanes                |Used only by chi (the non-linear step)                            |
|`complementLane`   |Flip all bits in a lane             |Used only by chi (NOT-AND pattern)                                |
|`rotL`             |Rotate a lane left by n bits        |Used by rho (lane rotation) and theta (column parity)             |
|`at`               |Read lane at (x,y) from flat array  |Converts 2D spec notation to 1D array index                       |
|`stateFromFn`      |Build a 25-lane state from a formula|Every step mapping produces a new state from (x,y) → lane         |
|`emptyState`       |All-zero 1600-bit state             |Starting point for absorption                                     |
|`bytesToLane`      |8 bytes → 1 lane (little-endian)    |Converts input bytes to the internal lane format                  |
|`laneToBytes`      |1 lane → 8 bytes (little-endian)    |Converts lanes back to output bytes                               |
|`xorBytesIntoState`|XOR a block of bytes into the state |The “absorb” operation of the sponge                              |
|`extractBytes`     |Read bytes out of the state         |The “squeeze” operation of the sponge                             |
|`theta`            |Column parity mixing                |Diffusion — spreads changes across columns                        |
|`rho`              |Lane bit rotation                   |Diffusion — spreads changes along the z-axis                      |
|`pi`               |Lane position shuffle               |Diffusion — rearranges the 2D grid layout                         |
|`chi`              |Non-linear row mixing               |**The only non-linear step** — provides cryptographic security    |
|`iota`             |XOR round constant into lane (0,0)  |Breaks round symmetry — prevents structural attacks               |
|`round`            |One full round (θ → ρ → π → χ → ι)  |Composition of all five step mappings                             |
|`keccakF1600`      |24 rounds of Keccak                 |The complete permutation — the heart of SHA-3                     |
|`padMessage`       |Pad input to block boundary         |Required by sponge construction, adds domain separation           |
|`sponge`           |Full absorb → squeeze pipeline      |The top-level algorithm that produces hash output                 |
|`squeezeLoop`      |Multi-pass squeeze for long outputs |Only needed for SHAKE XOFs requesting more than `rateBytes` output|
|`roundConstants`   |24 precomputed 64-bit constants     |Injected by iota to differentiate rounds                          |
|`rhoOffsets`       |25 precomputed rotation amounts     |Used by rho — each lane rotates by a different offset             |
|`b31`              |Bit 31 set (0x80000000)             |Helper for constructing round constants with high bits set        |