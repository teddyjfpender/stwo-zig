# Engineering Specification — stwo-zig milestone 0.1

This document describes the implemented milestone in this repository and the quality gates it must satisfy.

## Milestone 0.1 goals

1. Provide a **correct, tested M31 field implementation** for p = 2^31-1.
2. Provide a **correct, tested Circle group** implementation over M31 with a known generator of order 2^31.
3. Provide a minimal **Merkle tree VCS** primitive with proofs.
4. Provide a deterministic **Fiat–Shamir transcript** with challenge sampling into M31.
5. Provide a toy **proof-of-work** helper used for transcript grinding and negative tests.

## Quality gates

All changes must keep the following gates green:

- `zig build test`
- `zig build fmt`

## Correctness requirements

### M31 field

- Canonical representation: value is always in `[0, p-1]`.
- `fromU64(x)` implements reduction consistent with Mersenne prime reduction.
- `inv(a)` rejects `a=0` and otherwise satisfies `a * inv(a) = 1`.
- Serialization uses **little-endian** 4-byte canonical values.

### Circle group

- A point `(x,y)` is *on-circle* iff `x^2 + y^2 = 1 (mod p)`.
- Group law is complex multiplication:
  - `(x1,y1) ⊗ (x2,y2) = (x1*x2 - y1*y2, x1*y2 + y1*x2)`.
- Identity is `(1,0)`.
- Inverse is `(x, -y)`.
- Generator `g` (derived from tangent parametrization `t=2`) must satisfy:
  - `g^(2^30) = (-1,0)`
  - `g^(2^31) = (1,0)`

### Merkle tree

- Leaf hash and node hash are domain separated.
- Inclusion proofs verify for all leaf indices.
- Corrupting any sibling in the path must invalidate the proof.

### Transcript

- Two transcripts with identical sequence of `absorb` calls must produce identical challenges.
- Changing the label changes the output (domain separation).
- `challengeM31()` uses rejection sampling and never returns an out-of-range canonical value.

### PoW

- `verify(challenge, nonce, difficulty)` checks leading zero bits of the digest.
- `solve(challenge, difficulty, max_iters)` returns a nonce that verifies, or `null`.

