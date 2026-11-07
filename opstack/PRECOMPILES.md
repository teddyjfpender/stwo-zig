# Precompile provider integration

The `precompiles` guest variant installs an explicit provider through pinned
Revm's `Crypto` interface before any EVM executes. OP Revm still owns fork
activation, gas, input padding and EVM error handling. Installation failure traps;
it does not silently switch to another provider. The reference host is unchanged.

| Operation | Implementation | Boundary |
|---|---|---|
| SHA-256 | Existing admitted compression service | All input/padding lengths |
| Modexp | Existing admitted `(a*b+c) mod m` relation | Base and modulus up to 256 bits, arbitrary exponent byte length; even moduli supported |
| Larger modexp | Pinned software implementation | No truncation or odd-modulus assumption |
| BN254 G1 add | Existing admitted affine add/double services | Canonical on-curve input validation; infinity, doubling and inverse points handled in guest |
| BN254 G1 multiply | Same services, optional four-bit joint GLV window | Validates point before zero-scalar shortcut; reduces scalar modulo group order |
| Pairing, P256, RIPEMD, Blake2, BLS/KZG | Pinned provider defaults | Full software semantics; not replaced by unchecked hints |

The BN254 window follows the existing evmone integration. Packet construction
avoids zero-then-fill memory-service calls. Partial affine service preconditions
are discharged explicitly before every call. These operations reuse the existing
native and recursive service roster; no new AIR, transcript or tag is introduced.

Native differential tests cover zero/one/even moduli, leading zeros, exponents
longer than 256 bits, wider fallback, malformed/noncanonical points, infinity,
inverse points, order-boundary scalars, randomized multiplication and SHA padding.
The first checkpoint also replays five mainnet blocks against native Kona and
Unicorn. Those blocks do not exercise BN254 G1 or modexp, so that execution
checkpoint does not qualify their RV64 service paths or physical proof cost.
The default guest remains unchanged until explicit service-path and complete
proof/receiver receipts justify promotion.

## Explicit optimized variant

`optimized` adds bounded, exact-byte pairing memoization and admitted JUMPDEST
analysis. The pairing provider validates canonical/on-curve/subgroup inputs;
even an infinity G1 does not skip G2 validation. It retains up to 16 validated
G2 values and their lazily prepared line coefficients and eight computed results (at most 16 pairs per result). Failed inputs
are never cached. Larger inputs follow the pinned implementation. Repeated data
still pays Revm's fork-specific gas; the cache changes computation only.

JUMPDEST uses the existing service for 256-byte through 1-MiB code. A dedicated
64-aligned immutable byte owner provides initialized PUSH/STOP lookahead padding;
logical bytecode length and destination bitmap length stay unchanged. Smaller
and larger code retains the original scanner. No borrowed source is overwritten.

The 27,255,387-gas historical OP Mainnet block 121065789 exercises 19,622 admitted
G1 additions and 63,408 doublings. Native Kona, RV64 and the independent Unicorn
oracle agree on the final output and exact instruction count. This validates
execution of those service paths; a full physical proof of that heavy block is
still required. Modexp acceleration still needs a mainnet execution fixture that
actually invokes it. See the round-two receipt directory for exact ELF identities.

## Canonical field and GLV variants

`canonical` replaces only the guest BN254 base field with canonical storage
(R=R2=1), using the admitted arith256 relation and plain Fp2 service. Scalar Fr,
default Ark configurations and the native host retain their pinned implementation.
`canonical-glv` adds a 128-bit joint-window split using Arkworks' BN254 lattice.
`tools/derive_bn254_glv.py` reproduces constants and bounds; 1,024 random scalars
and boundary cases check reciprocal quotients against full-width division and
recombine signed components modulo the group order. No host quotient is trusted.

The combined guest passes all six exact mainnet execution/replay checks. On block
121065789, it makes 19,465 G1-add and 31,908 G1-double service calls and 928,200
plain-Fp2 calls. It retires 625,046,890 instructions and uses 40,326,924 service
RAM words. This is execution evidence; physical proving and recursive-root
qualification must be reported separately. All precompile fork rules remain in
Revm, and unsupported acceleration widths still execute the pinned software.

## Optional positive pairing advice

Build `canonical-glv-hinted` and run `benchmark.py --pairing-hints`. The host
generates a bounded trailer after replaying the original OPX input. The benchmark
records the original and extended input hashes, added bytes and host generation
wall time. The ordinary host reference still runs on the original input.

The guest validates the points and subgroup as usual. For a positive result it
can check the residue identity from [ePrint 2024/640](https://eprint.iacr.org/2024/640).
Let `L = p³ − p² + p + 6x + 2`, where `p` is the base modulus, `r` the scalar
order and `x` the BN seed. The guest checks a nonzero seed and its inverse and
requires `f · c · w^L = 1` for the Miller value `f` and `c` in Fq6. Since `r`
divides `L` and is coprime to `p⁶ − 1`, the identity implies
`f^((p¹² − 1)/r) = 1`. Seeding the signed Miller loop absorbs the `6x + 2`
part without another exponentiation. Missing or unsuccessful advice uses the
ordinary final exponentiation.

The host projects the 27-primary component of the pairing kernel into Fq6 and
extracts the negative L-th root in the remaining subgroup. The checked exponent
derivation is in `opstack/tools/derive_pairing_residue.py`. Advice ordinals only
select which field elements to try. The EVM result always comes from guest
arithmetic, and the RV64 proof binds the exact extended input.

The hinted guest also retains up to 16 exact single-pair Miller factors.
A key binds the normalized G1 point and the same validated prepared G2 owner.
It computes a factor inside the guest on the third encounter and multiplies it
back into the combined accumulator. Shared squaring and sparse line
multiplication distribute over this product, so both seeded and ordinary
Miller values are identical to the uncached loop. Eviction can only increase
the work. The cache also applies when the supplied residue fails its check.
