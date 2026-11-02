# Proposal: BLS12-381 Fp/Fp2 Montgomery product services (KZG point evaluation)

Status: **candidate, measured; largest single saving among the curve families.
Recommended.** Execution-only evidence; not promotable.

## Motivation (measured, evmone client, 15-block basket, 2026-11-01)

The basket's only BLS12-381 work is the KZG point-evaluation precompile (0x0a).
There are 5 calls on 4 blocks and no EIP-2537 calls. Each call cost about **40M
instructions** in blst's portable C:

- `mul_mont_n` takes 1,233 instructions per 384-bit Montgomery product on
  RV64IM, with 24,014 calls per evaluation (74% of the cost).
- The rest is Fp2/Fp6/Fp12 glue, linear ops, G1 doubling and control.

| Set | instr/gas | Δ instr | bits/gas | Δ bits (low / nominal / high cost) |
|---|---:|---:|---:|---|
| scored | 5.283 | -6.54% | 75,252 | -4.61% / -4.56% / -4.48% |
| holdout | 4.468 | -7.76% | 63,409 | -5.45% nominal |
| all | 5.122 | -6.75% | 72,914 | -4.72% nominal |

All guards pass with exact outputs. Mix-adjusted: -3.82%.

- Per evaluation: 33.05M instructions were saved, using 7,303 arith384_mont
  calls and 6,767 Fp2 products. That is 157M service cells against 5.12G CPU
  cells saved, about **33x cheaper**.
- The BLS bucket fell from 0.460 to 0.088 instr/gas. About 0.013 of the
  remainder is unrelated `vec_`/`ct_` helpers that the bucket regex also
  matches. Another 7M instructions per evaluation are linear Fp ops and
  control.

## ABI

- `0x0003_0121` `arith384_mont {a, b, m, r}`: `r = a·b·2⁻³⁸⁴ mod m`, m odd.
- `0x0003_0112` `bls12_381_fp2_mul {r, a, b}`: Montgomery Fp2 product.

blst keeps every element in Montgomery form, so the services do too. The row
`a·b = r·2³⁸⁴ + q·m` costs the same as the plain form, and blst stays
unchanged. Patch 0021 hooks `mul_mont_n` / `mul_mont_nonred_n` for 384-bit
operands and `mul_fp2` / `sqr_fp2`. This covers KZG, and every EIP-2537
operation (G1/G2 add and MSM, pairing, map-to-curve), because they all reduce
to these products.

`bls12_381_g1_add/double` (affine, Montgomery) and `arith384_mod` are defined
and tested in the executor but unused: blst's G1 code is Jacobian and already
rides on the field services. A KZG rewrite on affine G1 services (ZisK's route)
would save part of the remaining 7M per evaluation.

## AIR sketch

- **arith384_mont:** one 384-bit product row (48 byte limbs, 95 carries, a
  quotient up to 2³⁸⁴, `r < m`, m odd).
- **Fp2 product:** two two-product relations with p fixed.

Operands come through the word16 bridge and RAM via pointer words. Estimates
8,500 and 14,000 cells. A fixed-p `bls12_381_fp_mul` would save the modulus
read (about -1,500 cells).

## Expected effect

About -6.8% instructions and -4.7% committed bits over the basket. On a block
with one point evaluation, about 33M instructions are saved, roughly 1.5 instr/gas
on a 22M-gas block. Blob-heavy rollup blocks that call 0x0a gain the most.

## Found on the way

blst's `quot_rem_n` assumes an even limb count. With 64-bit limbs
(client patch 0002), `quot_rem_64` passes n = 1 (`div_by_z` in `blst_p2_mult`'s
GLS split). That is undefined behaviour, and it trapped in the host test.
EIP-2537 G2 MSM with one pair would hit it in the guest. Fixed by
`client_evmone/patches/0022-blst-rv64-quot-rem-single-limb.patch` (applies to
admitted builds too; basket counts are unchanged).

## Prover work

Product chip at 384 bits, pointer-packet bridge, services lane and receiver,
recursion support, and adversarial tests (even modulus, `r ≥ m`, non-canonical
outputs).
