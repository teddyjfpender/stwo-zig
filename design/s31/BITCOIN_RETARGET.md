# First Bitcoin retarget: exact constrained arithmetic

The [first-retarget gadget](../../src/frontends/s31/bitcoin_retarget.zig)
computes the required mainnet `nBits` for block height 2016 from block
2015's timestamp. The [standalone native proof test](../../src/frontends/s31/bitcoin_retarget_proof_test.zig)
proves this relation and publishes the input timestamp. It is **not yet
called by the recursive fold**. The current fold key still ends at height
2015. A future caller must bind the input time to the verified child state
and establish height 2016 before using this gadget as a chain consensus claim.

## The Core calculation

At height 2016, Bitcoin Core chooses the first block of the preceding
2016-block period, which is mainnet genesis at height zero. It subtracts
genesis time `1231006505` from block 2015's time, clamps the signed result
to `[302400, 4838400]` seconds, and calculates

```text
old_target = 0xffff * 2^208                 # nBits 0x1d00ffff
raw        = floor(old_target * clamped / 1209600)
limited    = min(raw, 2^224 - 1)            # mainnet powLimit
next_nBits = BitcoinCore.GetCompact(limited)
```

These are the exact [mainnet parameters](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/kernel/chainparams.cpp#L126-L128),
[genesis header time and bits](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/kernel/chainparams.cpp#L154-L160),
[adjustment arithmetic](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/pow.cpp#L36-L84),
and [compact encoding](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/arith_uint256.cpp#L196-L217).
The `powLimit` is `2^224 - 1`; it is slightly larger than the target decoded
from `0x1d00ffff`, which is `0xffff * 2^208`. Their difference is
`2^208 - 1`. The [S31 host target decoder](../../src/frontends/s31/relation.zig)
now uses the Core `powLimit`, while the first-epoch fold continues to enforce
the exact genesis bits.

For a hand example, a block-2015 time at most `genesis + 302400` gives the
minimum clamped span. Then `raw = old_target / 4`; Core's compact result is
`0x1c3fffc0`. At elapsed time `604809`, the compact result is
`0x1c7ffffc`; one second later it becomes `0x1d008000` because the top
mantissa byte reaches `0x80` and Core shifts it into an extra exponent byte.
At elapsed time `1209600`, the result is `0x1d00ffff`. Longer spans can
raise the raw target, but capping and compact encoding still return the
mainnet limit's compact value.

## The circuit relation

The time input is a packed `u32` with two constrained `u16` limbs. Two
integer borrow comparisons select the lower clamp, the signed middle
interval, or the upper clamp. The middle interval lies below the M31
modulus; its difference from genesis is therefore exact in M31. The selected
timespan is constrained to the corresponding value.

The gadget witnesses the 32 bytes of `old_target * timespan`, the 32 bytes
of the quotient, and the remainder. Every byte is decomposed into eight
Boolean bits. It enforces, from least to most significant byte,

```text
old_byte * timespan + carry = product_byte + 256 * next_carry
quotient_byte * 1209600 + carry = product_byte + 256 * next_carry
```

The second recurrence starts with `carry = remainder`, and both finish with
zero carry. Carries have a low `u16`, seven more Boolean bits, and a proof
that they are at most `4838400`. The remainder is additionally proved
smaller than `1209600`. Each side of each byte equality is below the M31
modulus, so the field equations enforce integer multiplication and unique
Euclidean division; modular wrap cannot substitute a different quotient.

The circuit caps the quotient at Core's `2^224 - 1`. It then looks at bit
seven of byte 27. If clear, compact exponent 28 takes bytes 25–27; if set,
exponent 29 takes bytes 26–27 after the Core sign-bit shift. The clamped
first-period quotient always has a nonzero byte 27, so these are the only
possible encodings. The resulting two serialized `u16` limbs must equal the
new header's `nBits` field. A claimed neighboring mantissa or exponent fails
the circuit.

## Native proof evidence and next integration

The S31 circuit suite accepts exact compact values and rejects changed
mantissa or exponent at the lower clamp, upper clamp, sign-byte transition,
and signed time boundary. It also checks value-bearing and witness-free
circuits have identical gate lists. The opt-in `test-bitcoin-retarget-proof`
step checks ten boundary timestamps against one value-free preprocessed root.
It proves three cases under that root: a pre-genesis timestamp that exercises
the signed lower clamp, the compact sign-byte transition, and an upper-clamped
timestamp. The native verifier accepts their eight-word public
statements and rejects changed mantissa, exponent, or timestamp words. The
eight words are two compact `u16` limbs, the packed `u32` input time, height
2016, genesis time, old compact bits, target timespan, and a relation tag.
The fixed constants and gadget equations are part of the committed circuit.

A local ReleaseSafe run produced 320,780 bytes in 13.637 s for the pre-genesis
case, 318,726 bytes in 16.351 s for the sign-byte case, and 317,009 bytes in
7.850 s for the upper-clamped case. All three used
preprocessed root `f5869e55a919b2e9f3e706b47f9220cc5f3c6f7e7b3a517bad513b666b7c7519`,
FRI PoW 26, 70 queries, and fold factor 1. These sequential single-trial
times are test observations, not comparative benchmarks.
Neither proof authenticates a 2015-header chain. The input time is a public
claim in this standalone profile; its test derives the verification root from
the value-free circuit topology and does not publish a sealed deployment key.
A height-2016 recursive proof remains to be produced.

Integrating this first boundary requires a new fixed-key fold profile that
selects first-epoch bits at steps 0–2014 and this retarget relation at step
2015 without changing AIR topology. The current timestamp window already
authenticates block 2015's time, and genesis time is key-pinned. Later
retargets need additional authenticated state: the first timestamp of each
2016-block period and the previous period's `nBits`. Checked accumulated
work, contextual future-time policy, and best-chain selection are separate
remaining conditions.
