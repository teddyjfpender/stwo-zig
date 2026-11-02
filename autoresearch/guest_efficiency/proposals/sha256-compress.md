# Proposal: sha256_compress service

Status: **candidate, measured; strongest single service per committed bit.
Recommended for prover work.** Execution-only evidence; not promotable.

## Motivation (measured, 15-block basket, 2026-11-01)

The guest computes the EIP-8025 `new_payload_request_root` with
`libssz-merkle`, which uses `sha2 0.10.9`. In the baseline attribution,
`sha2::sha256::compress256` is the second-hottest function: 11.22M of 104.27M
instructions on block 24,628,607.

| Set | instr/gas | Δ instr/gas | committed bits/gas | Δ bits/gas |
|---|---:|---:|---:|---:|
| scored | 12.092 | -1.788 (-12.9%) | 141,303 | -17,407 (-10.97%) |
| holdout | 10.158 | -1.599 (-13.6%) | 118,931 | -15,572 (-11.58%) |
| all | 11.710 | -1.750 (-13.0%) | 136,886 | -17,045 (-11.07%) |

All guards pass. The comparison is with the same-tree reference build
(13.880 / 11.757 / 13.461 instr/gas).

- There were 196,254 compressions over 15 blocks. Block 24,628,607 used 2,772.
- Each compression in software cost about **3,980 instructions** including glue,
  about 616k cells. The service costs about 18k cells plus about 30 packet
  instructions, which is about **27x cheaper**.
- On block 24,628,607 the `ssz_statement_sha256` bucket fell from 11.29M to
  0.35M instructions, and `ssz_input` from 1.14M to 0.94M.
- The saving holds at both ends of the cost range: -10.82% to -11.08% bits/gas.
- With the instruction mix taken into account, the estimate is -8.1%. SHA-256 is
  ALU-heavy, so the flat per-instruction proxy overstates its saving a little.

## ABI

Tag `0x0003_0010`. The packet is 12 u64:

- H0..H7 as little-endian u32 values, H0 in the low half of word 0;
- then the 64-byte block in stream order.

Only the state is written. The guest side is a vendored `sha2 0.10.9` (pinned in
`vendor/sha2-source.json`) with a `stwo-candidate-sha256` cfg backend:
`compress256` makes one ECALL per block and keeps the state in the packet across
blocks.

The ECALL also serves the EVM SHA-256 precompile (0x02), because `revm-precompile`
uses the same crate.

## AIR sketch

- **Truth AIR, one round per row.**
  - Bit columns for `a`, `e` and `w`: 96 columns. b, c, d and f, g, h come from
    row offsets -1..-3.
  - Six 16-bit-half carries for the `new_a`, `new_e` and `w_t` sums.
  - Booleanity constraints on all bits.
  - Σ0, Σ1, σ0 and σ1 are bitwise XORs of three bits (degree 3), Ch is degree 2,
    Maj is degree 3.
  - K_t is a preprocessed column.
  - 64 round rows plus 8 rows for loading and the feed-forward, so 72 rows per
    compression.
  - The feed-forward `H_i + v_i` is a carried 32-bit add.
- **Bridge.** It reads the 12 packet words and writes 4, through Keccak-style
  word16 bridge rows. The IO tuple ties the bridge's words to the truth AIR's
  packed state and message words.

**Soundness obligations:**

- correct packing of bits into 16-bit halves;
- carries range-checked so that each sum is exact mod 2^32;
- message schedule `w_t` for t ≥ 16;
- the round function matches FIPS 180-4;
- the bridge binds the packet bytes to the big-endian message words. The block
  bytes are in stream order, so the AIR byte-swaps inside the u64 limbs.

Adversarial tests should include all-ones blocks, carries at their maximum, and
the FIPS "abc" vector and NIST two-block vectors. The executor already passes
the FIPS "abc" vector and a two-block check against `std.crypto`.

## Estimated prover work

**18,000 cells per call**, range 12k-26k. The truth AIR is 8.7k cells, the bridge
plus RAM 4.4k, and the 1.3 margin covers the rest
(see [candidate-service-costs.md](candidate-service-costs.md)).

It is a new truth AIR roughly a fifth the width of Keccak. The bridge reuses the
Keccak word16 bridge design, and recursion support is needed.

## Expected benefit

- **Current client:** -12.9% instr/gas and -11.0% committed bits/gas, measured.
- **evmone-class client:** any client that commits the same request root does the
  same number of compressions, since that number depends on the block's SSZ
  payload and not on the EVM.
  - At about 3-4 instr/gas before services, about 1.75 instr/gas of SHA-256
    would be **40-50% of the guest's instructions**.
  - That makes this the most valuable single service for the Move A+B landing
    point.
  - This should be confirmed when the evmone port runs. If it reads ZisK's input
    format it must still hash the SSZ payload for the root.
