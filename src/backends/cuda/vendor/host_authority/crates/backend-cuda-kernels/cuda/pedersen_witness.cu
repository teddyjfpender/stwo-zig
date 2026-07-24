// Device witness generation for the Cairo Pedersen family (witness-on-GPU W3
// phase 2 — the pedersen partial_ec_mul cohort, see gpu_benchmarks/
// WITNESS_ON_GPU.md round-8 addendum and gpu_benchmarks/ROAD_TO_10MHZ.md P1).
//
// SCOPE OF THIS FILE (read before enabling the lane on hardware).
//
// The pedersen family targeted by workstream B is:
//   * partial_ec_mul_window_bits_18 (3.02s, 6693-line generated writer)
//   * partial_ec_mul_generic         (1.59s, 4376-line generated writer, 624 cols)
//   * pedersen_aggregator_window_bits_18 (2.04s, 695-line writer)
//
// Unlike blake_g (53 columns of 32-bit ops) and memory_id_to_big (a mechanical
// 9-bit limb split), the partial_ec_mul base-trace writers are full fp256
// EC-mul GADGET evaluations: 600+ trace columns of 256-bit modular arithmetic
// with per-limb range-check decompositions, feeding ~18 range-check
// sub-component families across 150+ interaction columns each with a bespoke
// (value-tuple, multiplicity, sign) map. That base-trace body is the irreducible
// hardware-completion item (it must be transcribed from the generated writer and
// qualified against the STWO_CUDA_WITNESS_VERIFY differential on a real GPU — it
// cannot be validated in a CUDA-stub / no-GPU session, and shipping an
// unvalidated fp256 witness kernel would violate the soundness-first contract).
//
// WHAT THIS FILE PROVIDES (the reusable, structurally-verifiable core):
//   1. pedersen_pair_logup   — one pair-batched logup column, generalized from
//      the proven blake_g_pair_logup / memory_rc_pair_logup kernels: two
//      combine() denominators over arbitrary-arity value tuples, explicit
//      multiplicity columns and per-side signs (the generated writers use
//      num = d0*m1 + d1*m0, d0*m1 - d1*m0, and d1*m0 - d0*m1 — all covered by
//      the two sign flags).
//   2. pedersen_multi_logup  — the final relation column: combine() over N value
//      columns, numerator (+/-)mult (generalized blake_g_final_logup /
//      memory_logup_inputs).
// The device finalize (fraction chain, claimed sum, shift, prefix sums) is the
// shared finalize_device_raw_logup lane (memory_witness.cu) — no new code.
//
// These kernels let the pod session move each component's interaction trace onto
// the device reading device-resident base columns, and are byte-identical by the
// same associativity/uniqueness argument proven for blake/memory. The base-trace
// gadget kernels land alongside them, per component, behind the differential.
//
// Field semantics match the host exactly (see fields.cuh): m31/cm31/qm31 add,
// sub, mul, neg are the M31 tower ops; combine([rel, v...]) =
// alpha[0]*rel + sum_i alpha[1+i]*v_i - z, matching relations::combine.

#include "fields.cuh"
#include "utils.cuh"

namespace {

constexpr uint32_t PW_BLOCK = 256;

DEVICE_FORCEINLINE qm31 qm31_mul_m31(qm31 x, m31 s) {
    return qm31{cm31{mul(x.a.a, s), mul(x.a.b, s)}, cm31{mul(x.b.a, s), mul(x.b.b, s)}};
}

// qm31 negation (fields.cuh defines neg for m31/cm31 only): negate each coord.
DEVICE_FORCEINLINE qm31 qm31_neg(qm31 x) { return qm31{neg(x.a), neg(x.b)}; }

// combine([rel, v_0 .. v_{n-1}]) = alpha[0]*rel + sum_i alpha[1+i]*v_i - z.
// `vals` is `n_vals` device column pointers; `alpha` has `n_vals + 1` entries.
DEVICE_FORCEINLINE qm31 combine_cols(
    const uint32_t *const *vals, uint32_t n_vals, uint32_t rel,
    const qm31 *alpha, qm31 z, uint32_t row) {
    qm31 acc = qm31_mul_m31(alpha[0], rel);
    for (uint32_t i = 0; i < n_vals; ++i) {
        acc = add(acc, qm31_mul_m31(alpha[1 + i], vals[i][row]));
    }
    return sub(acc, z);
}

// One pair-batched logup column with explicit multiplicities and signs.
//
//   d0 = combine([rel0, vals0...]),  d1 = combine([rel1, vals1...])
//   num = sign0 * (d0 * m1) + sign1 * (d1 * m0)
//   den = d0 * d1
//
// The three generated numerator shapes map as:
//   d0*m1 + d1*m0  -> (sign0=+1, sign1=+1)
//   d0*m1 - d1*m0  -> (sign0=+1, sign1=-1)
//   d1*m0 - d0*m1  -> (sign0=-1, sign1=+1)
// Both value tuples share the family arity `n_vals` (they are the same relation
// family within a pair). `m0`/`m1` are multiplicity column pointers (never null:
// pass the same column for both when the writer used a single mult).
__global__ void pedersen_pair_logup_kernel(
    const uint32_t *const *vals0, uint32_t rel0,
    const uint32_t *const *vals1, uint32_t rel1,
    uint32_t n_vals,
    const uint32_t *m0, const uint32_t *m1,
    int32_t sign0, int32_t sign1,
    uint32_t column_length,
    const qm31 *alpha,  // n_vals + 1 entries
    qm31 z,
    qm31 *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    qm31 d0 = combine_cols(vals0, n_vals, rel0, alpha, z, row);
    qm31 d1 = combine_cols(vals1, n_vals, rel1, alpha, z, row);
    qm31 t0 = qm31_mul_m31(d0, m1[row]);
    qm31 t1 = qm31_mul_m31(d1, m0[row]);
    if (sign0 < 0) t0 = qm31_neg(t0);
    if (sign1 < 0) t1 = qm31_neg(t1);
    qm31 num = add(t0, t1);
    denoms[row] = mul(d0, d1);
    num0[row] = num.a.a;
    num1[row] = num.a.b;
    num2[row] = num.b.a;
    num3[row] = num.b.b;
}

// The final relation logup column for a component:
//   den = combine([rel, vals...]) over `n_vals` value columns,
//   num = (neg ? -mult : mult, 0, 0, 0).
__global__ void pedersen_multi_logup_kernel(
    const uint32_t *const *vals, uint32_t n_vals, uint32_t rel,
    const uint32_t *mult,
    int32_t neg_num,
    uint32_t column_length,
    const qm31 *alpha,  // n_vals + 1 entries
    qm31 z,
    qm31 *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    denoms[row] = combine_cols(vals, n_vals, rel, alpha, z, row);
    num0[row] = neg_num ? neg(mult[row]) : mult[row];
    num1[row] = 0;
    num2[row] = 0;
    num3[row] = 0;
}

}  // namespace

extern "C" void pedersen_pair_logup(
    const uint32_t *const *vals0, uint32_t rel0,
    const uint32_t *const *vals1, uint32_t rel1,
    uint32_t n_vals,
    const uint32_t *m0, const uint32_t *m1,
    int32_t sign0, int32_t sign1,
    uint32_t column_length,
    const uint32_t *alpha,  // (n_vals + 1) qm31s, element-major
    qm31 z,
    uint32_t *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t blocks = (column_length + PW_BLOCK - 1) / PW_BLOCK;
    pedersen_pair_logup_kernel<<<blocks, PW_BLOCK>>>(
        vals0, rel0, vals1, rel1, n_vals, m0, m1, sign0, sign1, column_length,
        reinterpret_cast<const qm31 *>(alpha), z,
        reinterpret_cast<qm31 *>(denoms), num0, num1, num2, num3);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

extern "C" void pedersen_multi_logup(
    const uint32_t *const *vals, uint32_t n_vals, uint32_t rel,
    const uint32_t *mult,
    int32_t neg_num,
    uint32_t column_length,
    const uint32_t *alpha,  // (n_vals + 1) qm31s, element-major
    qm31 z,
    uint32_t *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t blocks = (column_length + PW_BLOCK - 1) / PW_BLOCK;
    pedersen_multi_logup_kernel<<<blocks, PW_BLOCK>>>(
        vals, n_vals, rel, mult, neg_num, column_length,
        reinterpret_cast<const qm31 *>(alpha), z,
        reinterpret_cast<qm31 *>(denoms), num0, num1, num2, num3);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}
