# Candidate service cost estimates (2026-11-01)

Machine-readable copy: [candidate-service-costs.json](candidate-service-costs.json),
in the same shape as `calibration.json` `candidate_services`. `calibration.json`
is frozen and unchanged; runs that use these numbers swap them in at load time
(notes/candidate-services-abi.md). They are **estimates from paper AIR designs**,
not measured tiers. A qualified AIR's `cost.json` replaces them.

| Service | cells/call | cells/byte | Range (call; byte) | Equivalent CPU instructions |
|---|---:|---:|---|---|
| memcpy | 1,500 | 40 | 1,000-2,500; 28-55 | 9.7 + 0.26/byte |
| memset | 1,300 | 20 | 900-2,000; 13-28 | 8.4 + 0.13/byte |
| memcmp | 2,000 | 45 per examined byte | 1,300-3,000; 30-60 | 12.9 + 0.29/byte |
| sha256_compress | 18,000 | 0 | 12,000-26,000 | 116 |
| arith256 | 6,000 | 0 | 4,000-9,000 | 39 |
| arith256_mod | 6,500 | 0 | 4,500-10,000 | 42 |

These figures cover only the service's AIR work. The ECALL instruction and the
guest's packet set-up are ordinary instructions, already charged at 154.8
cells each.

## Building blocks (measured widths in this repository)

| Unit | Main | Interaction | Cells | Source |
|---|---:|---:|---:|---|
| closed_ram transition (one RAM word access, word16 limbs) | 28 | 68 | **96** | `air/memory/closed_ram/layout.zig` |
| Keccak word16 bridge row (one packet word, before/after bytes, RAM+OWNER+IO pairs, 41 range checks) | 66 | 116 | **182** | `air/delegations/keccak/word16_bridge/layout.zig` |
| secp word16 bridge row (one 32-byte coordinate = 4 words) | 134 | 244 | **378** (94.5/word) | `air/delegations/secp256k1/word16_bridge/layout.zig` |
| secp product row (256-bit modular multiply, byte limbs) | 319 | 384 | **703** | `air/delegations/secp256k1/layout.zig` |
| Keccak truth (2 permutations per 29-row slot) | 1,923 | 2,596 | 65,525 per permutation | `air/delegations/keccak/layout.zig` |
| load/store v2 row (one memory instruction) | 70 | 32 | 102 | `air/memory/load_store_v2/layout.zig` |

Cross-check: Keccak truth 65,525 plus 25 bridge rows × 182 = 70,075 cells per
call, against the calibrated 72,159. The rest is RAM-side work and padding. A
margin factor of **1.3** (power-of-two padding, intermediate columns that
degree-3 limits force, shared preprocessed columns) is applied to every raw
total below, then the result is rounded up.

## memcpy (DMA-style, after ZisK Dma / Dma64Aligned / DmaUnaligned / DmaPrePost)

- **Body row, one per 8 destination bytes.** Main columns (about 40):
  - destination and source word-address limbs;
  - tick;
  - 8 realignment bytes (a source byte shift spans two source words, carried row to row);
  - 4 destination-before limbs;
  - count and active flags.

  Interaction columns (about 20): source RAM read, destination RAM write, 4
  paired byte range checks and continuation, for 7 fractions in 4 pairs. That
  is 60 cells for the row plus two closed_ram transitions (192), so 252 per 8
  bytes = 31.5 cells/byte. With margin: 41, rounded to **40**. The aligned case
  is cheaper (no byte columns, about 28 cells/byte).
- **Per call:**
  - 3 packet words through a bridge plus RAM (3 × 190);
  - head and tail partial-word rows with byte masks (2 × (120 + 96));
  - a descriptor row tying the ECALL row to the DMA bus (about 100).

  That is about 1,100 cells; with margin, **1,500**.
- **ZisK comparison.** ZisK uses 1 Dma row per call, 1 Dma64Aligned row per 4-8
  words and 1 DmaUnaligned row per word, about 30 columns of 64-bit cells, plus
  its Mem rows (12 columns per access lane). Our 31-bit field needs word16
  limbs, so the RAM side (96 cells per access) dominates.

## memset

- **Body row:** about 13 main and 8 interaction columns (RAM write plus
  continuation), plus one RAM transition (96). That is 117 per 8 bytes = 14.6/byte.
  With margin, 19, rounded to **20**.
- **Per call:** 3 packet words (570), head and tail (2 × 156) and a descriptor
  (100), about 980. With margin, **1,300**.

## memcmp

- **Body row, per 8 examined bytes:** about 23 main columns (two addresses, tick,
  two 4-limb values, count) and 12 interaction columns, plus two RAM read
  transitions. That is 28.4/byte, 37 with margin. Unaligned operands add byte
  columns, so **45**.
- **Per call:**
  - 4 packet words read and 1 written (5 × 190);
  - a first-difference row with byte one-hot, inverse witness and an unsigned
    `<` lookup (about 100);
  - head and tail (300);
  - a descriptor (100).

  That is about 1,450; with margin, **2,000**.

## sha256_compress

- **Truth AIR.** ZisK's Sha256f has 102 bit columns × 72 rows per compression on
  Goldilocks. Rebuilt for M31, each round row has:
  - a, e and w as 96 bit columns;
  - 6 half-word carries, because the 32-bit sums of up to 7 terms exceed 2^31
    and are split into 16-bit halves;
  - 3 control columns.

  That is 105 main columns. The 3 range-check pairs for the carries add 16
  interaction columns. Σ0, Σ1, Ch and Maj are degree ≤ 3 in the bit columns.
  b/c/d and f/g/h come from row offsets, and K is a preprocessed column. In
  total, 72 rows × 121 = 8,712 cells.
- **IO to the bridge:** 16 words, about 600 cells.
- **Bridge:** 12 words read and 4 written via Keccak-style word16 bridge rows
  plus RAM, 16 × (182 + 96) = 4,448.
- **Total:** 13,760 raw; with margin, **18,000**, about a quarter of a Keccak-f
  call.
- **Plausibility check against Keccak:** Keccak truth costs about 1.7 cells per
  state bit per round. 64 SHA rounds × 96 fresh bits × 1.7 ≈ 10.4k cells, which
  agrees with 8.7k.
- **Range 12k-26k.** The upper end covers needing packed-word intermediates for
  degree, or a separate message-schedule table.

## arith256

- **Truth:** one row shaped like the secp product row (703 cells). It proves
  `a*b + c = hi*2^256 + lo` as a byte-limb convolution with 63 carries, the same
  shape as `a*b = q*p + r` with p = 2^256.
- **Bridge:** 5 coordinates × 378 = 1,890.
- **RAM:** 12 reads + 8 writes = 20 × 96 = 1,920.
- **Total:** 4,513 raw; with margin, **6,000**.
- **ZisK comparison:** ZisK's ArithEq Arith256 variant is 19 columns × 16 rows of
  64-bit cells with 16-bit chunks. Its carries (±2^22, products near 2^37) do not
  fit M31, which is why the byte-limb secp row is used as the template.

## arith256_mod

- **Truth:** `a*b + c = q*m + r` with a quotient of up to 512 bits (for small m),
  an `r < m` borrow chain and an `m = 0` flag with inverse. About 450 main and 650
  interaction columns, 1,100 cells.
- **Bridge:** 5 coordinates (1,890).
- **RAM:** 16 reads + 4 writes (1,920).
- **Total:** 4,910 raw; with margin, **6,500**.

## Sensitivity

`rescore` (scratch) re-prices the same runs at the low and high ends without
re-executing (scored committed bits/gas, change against the same-tree reference
build):

| Variant | Low | Nominal | High |
|---|---:|---:|---:|
| all three memory services | -9.02% | -7.39% | -5.02% |
| sha256_compress | -11.08% | -10.97% | -10.82% |
| arith256 + arith256_mod | -0.60% | -0.58% | -0.55% |
| all services | -20.78% | -19.01% | -16.43% |

Every measured conclusion below holds across the whole range.

## Caveat: the proxy charges every instruction the same

The frozen proxy charges 154.8 cells for every instruction. A memory instruction
really costs about 198 cells more than an ALU instruction: a load/store v2 row
(102) plus a closed_ram transition (96).

Fitting this to the calibration block (32.1% memory operations) gives two
classes:

| Instruction class | Cells per instruction |
|---|---:|
| ALU | 91.3 |
| Memory | 289.3 |

Re-pricing the scored runs with this mix (a rough sensitivity check, not a
replacement score):

| Variant | Proxy | Mix-adjusted |
|---|---:|---:|
| memory services | -7.39% | -7.97% |
| sha256_compress | -10.97% | -8.05% |
| all services | -19.01% | -16.50% |

SHA-256 software is ALU-heavy, so the proxy slightly overstates its saving.
Bulk memory is load/store-heavy, so the proxy slightly understates its saving.
