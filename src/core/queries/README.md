# Candidate framed query sampler

`uniform_v1.zig` is an opt-in component for a future `S31NAT9F` proof. No
accepted prover or verifier uses it. The caller passes the verifier's 32-byte
channel digest after the accepted final FRI proof-of-work nonce and the query
event ordinal derived from the verified protocol schedule. These are
**preconditions**, not checked by this module.

For block counter `c`, the sampler hashes exactly

```text
BLAKE2s-256(
  ASCII("S31BCS2")      // seven bytes
  || 0x04               // raw_word_draw role
  || LE64(36)           // payload length
  || LE64(query_event)  // verifier-derived stage
  || digest[32]
  || LE32(c)
)
```

The 32-byte output supplies eight little-endian `u32` words in order. The
counter may take each value from `0` through `2^32−1` once; the next draw
fails. A requested block budget above `2^32` is rejected before any draw,
also bounding all word-accounting fields without overflow. The sampler caps
consumed blocks and returns the raw position vector
in transcript order, including duplicates, plus counts of blocks, examined
words, rejected words, and discarded tail words. On failure, it frees the
partial vector and returns an error; the verifier must reject the proof.

For a FRI domain of size `2^k`, `0 ≤ k ≤ 31`, one position is
`word & (2^k−1)`. An ideal uniform 32-bit word has exactly `2^(32−k)`
preimages for each position, so this operation is exactly uniform and never
rejects a word. The existing S31 Lean theorem
`S31.Gadgets.PcsFri.RawMaskedQuery.preimages_exact` proves this count;
`ideal_raw_all_good_fraction` proves the with-replacement fixed-set query
probability **assuming independent uniform raw words**. These theorems do
not prove that BLAKE2s outputs independent words or that the complete FRI
verifier refines the paper protocol.

The generic bounded helper accepts domain sizes `1..2^32`. It discards a word
`w` when `w ≥ floor(2^32 / n) · n` and otherwise emits `w mod n`. There are
exactly `floor(2^32 / n)` accepted raw preimages for every output value.
Under independent uniform raw words, the emitted values are uniform
conditional on completing within the caller's block cap. The probability
of failing that cap is a separate protocol event that still needs a bound.

The native path's current M31-output BLAKE2s reduction occurs **before** its
mask and biases some positions. This module hashes raw BLAKE2s output using
the versioned role frame and never calls the M31-reducing hasher. Its framed
bytes match the candidate S31 `PCS_FRI_FRAMED_BCS_V2_DESIGN.md` model and
are checked against an independent `hashlib.blake2s` vector in Zig tests.

This module alone does not bind a package selector or verification key to the
new transcript, cover other FRI challenges, define the four-root proof wire,
prove adaptive Fiat–Shamir security, or establish a native PCS/FRI theorem.
