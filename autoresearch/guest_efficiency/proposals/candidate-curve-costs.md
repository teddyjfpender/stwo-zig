# Candidate curve, field and sponge service costs (2026-11-01)

Machine-readable copy: [candidate-curve-costs.json](candidate-curve-costs.json),
same shape as `calibration.json` `candidate_services`. `calibration.json` is
frozen; runs swap these entries in at load time together with
[candidate-service-costs.json](candidate-service-costs.json). These are
**estimates from paper AIR designs**, not measured tiers. ABI:
[../notes/candidate-curves-abi.md](../notes/candidate-curves-abi.md).

| Service | cells/call | cells/byte | Range (call) | ≈ CPU instructions | Used by the client |
|---|---:|---:|---|---:|---|
| bn254_g1_add | 10,100 | 0 | 7,000-16,000 | 65 | ecMul, ecAdd |
| bn254_g1_double | 8,200 | 0 | 5,500-13,000 | 53 | ecMul |
| bn254_fp2_mul | 9,600 | 0 | 6,500-15,000 | 62 | ecPairing |
| bls12_381_g1_add | 14,800 | 0 | 10,000-24,000 | 96 | no |
| bls12_381_g1_double | 12,000 | 0 | 8,000-19,000 | 78 | no |
| bls12_381_fp2_mul | 14,000 | 0 | 9,500-22,000 | 90 | KZG |
| arith384_mod | 10,800 | 0 | 7,500-17,000 | 70 | no |
| arith384_mont | 8,500 | 0 | 5,500-13,000 | 55 | KZG |
| keccak_sponge | 10,700 | 523 per rate byte (71,053 per permutation) | 7,000-18,000; 500-560 | 69 + 459 per permutation | Keccak > 64 bytes |

The ECALL and the guest's packet set-up are ordinary instructions, already
charged at 154.8 cells each.

## Building blocks

From `candidate-service-costs.md` (measured widths in this repository):

- closed_ram transition: 96 cells per word access;
- secp word16 bridge row: 378 cells per 32-byte coordinate (94.5 per word);
- secp product row (256-bit `a·b = q·p + r`, byte limbs, 63 carries): 703 cells;
- Keccak bridge row: 182 cells per word;
- Keccak truth: 65,525 cells per permutation (`air/delegations/keccak/layout.zig`).

Derived here:

- **Pointer packet word:** a bridge word plus a RAM read, about 190 cells (the
  memcpy estimate uses the same 3 × 190).
- **384-bit product row:** limbs, quotient and carries all scale linearly with
  the limb count, so 703 × 48/32 ≈ **1,055**. The bridge is 378 × 1.5 = 567 per
  48-byte coordinate.
- **Canonical output/input check (`x < p`):** a borrow chain over the limbs
  against the constant p, about 70 cells at 256 bits and 105 at 384 bits.
  ZisK's ArithEq has the same `x3_lt`/`y3_lt` columns.
- **Nonzero check** (`x1 ≠ x2`, `y ≠ 0`): one chunk-difference inverse, about
  100 cells. This is ZisK's `x_delta_chunk_inv` / `x_are_different`. Without it
  the affine relations are satisfiable by any λ when the guest passes equal
  points, so the check is a soundness requirement, not an optimisation.
- **Montgomery rows:** `a·b = r·2³⁸⁴ + q·m` has the same columns and carries as
  `a·b = q·m + r`, so it costs the same.
- **Margin:** 1.3 on every raw total (power-of-two padding, degree-3
  intermediates, shared preprocessed columns), as for the earlier candidates.

**Cross-check against a measured AIR.** The same building blocks applied to
the admitted secp RCB programs (add: 12 products, 4 small-constant products, 15
linear rows, 9 coordinates, 36 RAM words; double: 13 products, 6 linear rows, 6
coordinates, 24 words) give 20,356 and 14,611 raw cells. Weighted by the
calibration block's 11,496 adds and 9,768 doubles, that is 17,717 raw against
the measured **18,935** cells per call: measured/raw = 1.07. The 1.3 margin is
therefore conservative by about 20%.

## Curve operations (affine, as ZisK)

The affine formulas fold the linear terms into the product relations, so each
relation is one `a·b + linear = q·p` row:

- **Add:** `λ(x2 - x1) = y2 - y1`, `x3 = λ² - x1 - x2`, `y3 = λ(x1 - x3) - y1`,
  which is 3 rows.
- **Double:** `2λy = 3x²` (two products, 1.5 rows), plus `x3` and `y3`, which is
  3.5 rows.

λ is a witness (the AIR needs no inversion). That is why the affine form is far
cheaper than the Jacobian formulas evmone and blst use in software (16 and 7
products).

| | bn254_g1_add | bn254_g1_double | bls12_381_g1_add | bls12_381_g1_double |
|---|---:|---:|---:|---:|
| product rows | 3 × 703 = 2,109 | 3.5 × 703 = 2,461 | 3 × 1,055 = 3,165 | 3.5 × 1,055 = 3,693 |
| nonzero check | 100 | 100 | 150 | 150 |
| bridge coordinates | 6 × 378 = 2,268 | 4 × 378 = 1,512 | 6 × 567 = 3,402 | 4 × 567 = 2,268 |
| RAM words | 24 × 96 = 2,304 | 16 × 96 = 1,536 | 36 × 96 = 3,456 | 24 × 96 = 2,304 |
| pointer words | 3 × 190 = 570 | 2 × 190 = 380 | 570 | 380 |
| canonical checks | 6 × 70 = 420 | 4 × 70 = 280 | 6 × 105 = 630 | 4 × 105 = 420 |
| raw | 7,771 | 6,269 | 11,373 | 9,215 |
| ×1.3 | **10,100** | **8,200** | **14,800** | **12,000** |

## Field operations

- **bn254_fp2_mul** (ZisK `Bn254ComplexMul`):
  - `c0 = a0b0 - a1b1 + q0p` and `c1 = a0b1 + a1b0 - q1p`, each a two-product
    relation (1.5 rows): 2,109;
  - canonical outputs 140 (inputs need not be canonical);
  - 6 coordinates 2,268; 24 RAM words 2,304; 3 pointer words 570.

  Raw 7,391, so **9,600**.
- **bls12_381_fp2_mul:**
  - 3 × 1,055 = 3,165 (Montgomery rows);
  - 6 coordinates 3,402; 36 RAM words 3,456; 3 pointer words 570;
  - canonical outputs 210.

  Raw 10,803, so **14,000**.
- **arith384_mont:**
  - one 1,055 row, plus 10 cells for "m odd" (the low limb bit) and 105 for `r < m`;
  - 4 coordinates 2,268 (a, b, m read; r written); 24 RAM words 2,304; 4 pointer words 760.

  Raw 6,502, so **8,500**. A fixed-modulus variant (`bls12_381_fp_mul`) would
  skip the m read and save about 1,500 cells.
- **arith384_mod** (ZisK `Arith384Mod`):
  - arith256_mod's truth (1,100: 512-bit quotient, `r < m`, `m = 0` flag) × 1.5 = 1,650;
  - 5 coordinates 2,835; 30 RAM words 2,880; 5 pointer words 950.

  Raw 8,315, so **10,800**.

## keccak_sponge

`bytes` = 136 × permutations, so the per-byte term is a per-permutation charge.

- **Per permutation:**
  - Keccak truth 65,525 (measured);
  - absorbing the block:
    - 17 input words through RAM: 1,632;
    - byte realignment for unaligned input: 17 × 60 = 1,020;
    - 1,088 input bit columns XORed into the rate: about 1,100;
    - chaining the state from one permutation to the next inside the AIR: 500.

  The absorb is 4,252 raw, ×1.3 = 5,528. Total 71,053 per permutation, which is
  **523 per rate byte**.
- **Per call:**
  - the final 25-lane state through the Keccak bridge (4,550) and RAM (2,400);
  - 4 packet words (760);
  - the padding one-hot row (300) and the length/descriptor (200).

  Raw 8,210, so **10,700**. A non-fresh call also reads 25 lanes, about
  +9,000; the client never does this.
- **Comparison with the admitted service.** A one-block hash costs 81,753
  cells on the sponge against 72,159 for Keccak-f plus about 400 glue
  instructions (62k cells) on the admitted service. Intermediate states never
  leave the AIR.
- **Refinement not taken.** A digest-only output (4 lanes) would save about
  5,700 cells per call. The client only reads lanes 0..3. See
  [keccak-sponge.md](keccak-sponge.md).

## Comparison with ZisK

| AIR | Rows per op | Witness columns | Cells per op (64-bit Goldilocks) |
|---|---:|---:|---:|
| ArithEq (256-bit: arith256, secp256k1/r1, bn254 curve and complex ops) | 16 | about 45 (6 operands, q0-q2, s, 11 selectors and clock-0 flags, x-difference inverse, two lt bits, two deltas, 6 carries, step) | about 720 |
| ArithEq384 (bls12-381 curve and complex ops, arith384_mod) | 24 | 35 | 840 |

ZisK packs a whole affine operation into one 16 or 24-row cycle with 16-bit
chunks and 64-bit carries. Its operands reach the AIR through its Mem state
machine (separate rows). Our estimates per call (10,100 cells for a BN254 add,
31-bit cells) are about 7x ZisK's 720 64-bit cells in raw witness bits (313k vs 46k).

Two thirds of our raw total is the word16 bridge and closed-RAM traffic
(5,142 of 7,771 for bn254_g1_add), not the arithmetic. The same RAM-side
dominance shows in the bulk-memory estimates, and this is where an
operand-streaming bridge would pay most.

## Sensitivity (scored committed bits/gas vs the mem+sha+arith reference)

`rescore.py` (scratch) re-prices the same runs at the low and high ends of the
curve-service ranges (earlier services stay at nominal):

| Variant | Low | Nominal | High |
|---|---:|---:|---:|
| + bn | -4.12% | -4.00% | -3.81% |
| + bls | -4.61% | -4.56% | -4.48% |
| + keccak | -5.24% | -4.34% | -2.84% |
| + all three | -13.96% | -12.91% | -11.12% |

Mix-adjusted, with ALU instructions at 91.3 cells and memory instructions at
289.3 (candidate-service-costs.md), at nominal cost: bn -4.65%, bls -3.82%,
keccak -4.54%, all -13.01%. BN254 and BLS remove ALU-heavy carry chains, so the
flat proxy overstates them slightly. The Keccak absorb glue is
load/store-heavy, so the proxy understates it. Every family pays at every end
of the range.
