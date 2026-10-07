# S31 SHA256d chip integration contract

Status: SHA witness planning, a pinned SHA-side component profile, and caller
equations are implemented. A private circuit-to-chip SHA proof is **not yet
implemented**. Bitcoin proofs still use `sha256d.zig` in the generic circuit.
The existing six-call SHA STARK uses public boundary rows and is not a proof of
a private S31 header.

## The statement and the minimum private boundary

An S31 80-byte header has 40 little-endian `u16` limbs, and its SHA256d digest
has 16 little-endian `u16` limbs. A fast caller should bind only those 56
circuit values to the chip. The two intermediate compression states belong to
the SHA chip and caller AIR; copying SHA's whole round trace into the circuit
would keep the generic circuit's dominant cost.

For one header, the packed SHA graph has three compression calls. Each call
uses 24 input words (eight state plus 16 message words) and eight output
words. A `recursion_wire` tuple has six M31 coordinates:

```text
(call_id, wire_id, byte0, byte1, byte2, byte3)
```

The bytes are ordered from least significant to most significant **within
the SHA word**. SHA loads four serialized header bytes as a big-endian word.
For header bytes `h0 h1 h2 h3`, its tuple is `(h3,h2,h1,h0)`.
Call IDs are verifier-assigned `1..3` for one header, `1..6` for two. Source
boundary wire IDs are `4096..4119`; output wire IDs are the fixed graph's
`264..271`. The tuple convention is implemented in
[`sha_chip_plan.zig`](../../src/frontends/s31/sha_chip_plan.zig) and tested
against the packed SHA AIR's actual lookup events for both batch sizes.

## Caller polynomial equations

[`sha_caller_equations.zig`](../../src/frontends/s31/sha_caller_equations.zig)
specifies one caller row with 56 circuit limb values and 96 four-byte SHA
boundary words. Its **264 degree-one equations** apply over both M31 prover
rows and QM31 verifier openings. The first header limb is constrained by

```text
L0 − (call0.block0.byte3 + 256 × call0.block0.byte2) = 0.
```

The next limb uses bytes 1 and 0 of that same word. The other 38 input limbs
use the rest of the first block and the first four words of the second. The
16 digest limbs use the final call's eight output words in the same pattern.
The caller also constrains both initial SHA states, the second call's state to
the first call's output, the third call's first eight message words to the
second call's output, both `0x80` pad bytes, all zero pad bytes, and the exact
big-endian bit lengths 640 and 256. The caller code emits the 56 fixed-address
Gate tuples and 96 SHA word tuples that a joined component must use.

The limb equation is integer-sound **only if each byte is range checked**.
The packed source AIR requests two `range_check_8_8` table lookups per input
word. Packed SHA arithmetic's `word()` constructor requests the same lookups
for produced words, including the eight feed-forward outputs. The shared
`recursion_wire` lookup then makes the caller coordinates equal to those
byte-constrained SHA words. Tests intentionally replace `7 + 256×3` with
`263 + 256×2`: the local limb equation still holds over M31, while the SHA
wire multiset no longer closes. The range tables and every lookup sum are
therefore mandatory parts of the verifier, not optional witness checks.

## One-proof construction required for promotion

The first joined profile should use one Fiat–Shamir transcript, one base/main
commitment sequence, one interaction commitment, and one PCS/FRI proof for:

1. The S31 circuit AIR, with one additional authenticated Gate producer use
   at each of the 56 fixed private limb addresses.
2. A committed caller AIR evaluating the 264 equations above and consuming
   the corresponding Gate tuples. It emits the 24 input and consumes the
   eight output SHA tuples for each compression call.
3. SHA source, schedule, round, and feed-forward AIRs, plus their bitwise and
   range lookup tables. Their signed `recursion_wire` sums must cancel the
   caller's sums. Every table relation must also close.

The verifier must reconstruct fixed call IDs, wire IDs, component order,
semantic digests, row logs, table identities, challenge order, and the
fixed Gate addresses from a sealed key **before the first witness
commitment**. It must check Gate, SHA-wire, and table sums separately. The
existing `direct_arithmetic` private bridge proves this pattern for eight
repeated-step endpoints in one proof, but it is fixed to that chip and its
direct-M31 circuit profile. The SHA caller has 56 Gate limbs and 96 word
tuples and belongs initially to a new proof profile. The Bitcoin fold uses
the sparse-wide circuit and additionally needs its bridge generalized to
that profile. RISC-V SHA currently uses per-relation challenge elements,
whereas the S31 circuit uses one Gate challenge pair; the joined proof must
define and authenticate their complete draw schedule.

No prover-side equality check, matching host SHA computation, separate SHA
proof, or public-boundary row substitutes for those commitments and lookup
closures. Performance comparison becomes meaningful only after the same
private-header statement is proved and natively verified in both the generic
circuit and the joined chip profile, with setup, witness, proving, PoW,
verification, proof bytes, and memory recorded separately.
