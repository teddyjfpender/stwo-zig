# Proposal: arith256 / arith256_mod services

Status: **candidate, measured; small value on the current client. Defer the
decision until the evmone-class client is measured.** Execution-only evidence.

## Motivation (measured, 15-block basket, 2026-11-01)

The guest change routes these revm opcodes to the services:

| Opcode | Service | Notes |
|---|---|---|
| MUL | `arith256`, low half | Software path kept when both operands are below 2^64 |
| MULMOD | `arith256_mod` | |
| ADDMOD | `arith256_mod` | Computed as `a*1 + b mod n` |
| EXP | `arith256` | Square-and-multiply |

Results on the 15-block basket:

| Set | instr/gas | Δ instr/gas | committed bits/gas | Δ bits/gas |
|---|---:|---:|---:|---:|
| scored | 13.779 | -0.101 (-0.7%) | 157,791 | -918 (-0.58%) |
| holdout | 11.749 | -0.008 (-0.1%) | 134,466 | -38 (-0.03%) |
| all | 13.378 | -0.083 (-0.6%) | 153,186 | -745 (-0.48%) |

- **G5 (holdout generalises) fails.** The holdout blocks hardly use MUL, EXP or
  MULMOD, so they gain 0.07% against 0.73% on the scored set. This is a workload
  difference, not a basket special case. It does mean the service's value
  depends on the contract mix.
- There were 60,216 `arith256` and 35,077 `arith256_mod` calls over 15 blocks.
  Block 24,628,607 used 2,548 and 319, saving about 52 instructions per call.
- The 6,000-6,500 cells per call are worth about 40 instructions. Software
  `ruint` MUL is only about 60-80 instructions, so MUL gains little. MULMOD,
  ADDMOD and a long EXP gain much more, but they are rare in these blocks.
- The modexp precompile (aurora-engine-modexp) was not routed: the `other_crypto`
  bucket is empty on the attribution block.

## ABI

As in CONTEXT.md:

- `arith256`: `a, b, c` in, `lo, hi` out, with `hi:lo = a*b + c`;
- `arith256_mod`: `a, b, c, m` in, `r` out, with `r = (a*b + c) mod m` and
  `r = 0` when `m = 0`.

Each value is 4 little-endian u64 limbs.

## AIR sketch

Use one row per call, on the template of the secp product row: byte limbs, a
63-carry convolution and byte range checks. `arith256` proves
`a*b + c = hi·2^256 + lo`. `arith256_mod` proves `a*b + c = q·m + r` with:

- a 512-bit `q`;
- `r < m` shown by a borrow chain;
- an `m = 0` selector with an inverse witness that forces `r = 0`.

The bridge carries 5 coordinates through the secp word16 bridge.

ZisK's ArithEq (16-bit chunks on 64-bit cells, carries ±2^22) cannot be used as
it stands on M31.

## Estimated prover work

| Service | cells/call | Range |
|---|---:|---:|
| arith256 | 6,000 | 4k-9k |
| arith256_mod | 6,500 | 4.5k-10k |

Derivations are in [candidate-service-costs.md](candidate-service-costs.md).
This is the cheapest of the new truth AIRs because the secp product row already
exists.

## Expected benefit

- **Current client:** -0.6% committed bits/gas on the scored set and -0.03% on
  the holdout. This is not enough on its own to justify the prover work.
- **evmone-class client:** intx MUL is also about 60 instructions, so the
  absolute saving per opcode is similar. The share is about 3-4x larger at about
  3.5 instr/gas, so roughly -2% bits/gas on these blocks.
- The service becomes clearly worthwhile if the BN254 and modexp precompiles are
  ported onto `arith256_mod`, or if the client is changed to batch
  field arithmetic. Measure again with the evmone port before deciding.
