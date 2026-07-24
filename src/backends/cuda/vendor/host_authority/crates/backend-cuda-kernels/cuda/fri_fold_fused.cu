// Fused FRI triple fold (plan Step 3.4): ONE kernel performs the three
// consecutive sub-folds of a full `fold_step == 3` FRI commitment round as a
// single 8-to-1 reduction. Each thread owns one output element, reads its
// eight source elements once, and applies the three fold stages entirely in
// registers, so the input layer is read once instead of three geometric
// passes and no ping/pong intermediate is written.
//
// Byte identity with the per-fold kernel sequence
// (`fold_circle_into_line_device_alpha_kernel` / `stwo_gpu_lab_fold_line_device_alpha`,
// launched by `PreparedFriGraph::launch_fold` with alpha_squarings = 0, 1, 2):
//
//   1. Data dependence is strictly local: output element `i` of a triple fold
//      depends only on input elements `8i..8i+7` and on seven twiddles
//      (four stage-0, two stage-1, one stage-2). This kernel evaluates, per
//      output element, the exact same expression tree the three kernels
//      evaluate — the same `fields.cu` primitives (`add`, `sub`, `mul`,
//      `mul_by_scalar`) applied in the same order to the same operands. All
//      of these are exact integer/modular operations with deterministic word
//      results (no rounding, no reassociation), so regrouping the evaluation
//      by output element instead of by stage leaves every intermediate word
//      bit-identical.
//   2. Twiddle loads are identical: stage twiddle offsets are the host-side
//      `FoldLaunch::twiddle_offset` values of the three replaced launches,
//      and stage-`s` output index `out_index` addresses `domain` (or
//      `get_circle_twiddle`) exactly as the per-fold kernel at that stage
//      addresses it with thread index `out_index`.
//   3. The per-stage alphas come from the identical repeated-squaring chain
//      the per-fold kernels run on the device alpha (`alpha_squarings` loop):
//      alpha, mul(alpha, alpha), mul(alpha^2, alpha^2).
//   4. Round 0 only: the per-fold circle kernel accumulates
//      `dst = mul(dst, alpha_sq) + f'` onto a destination its launcher
//      memsets to zero. This kernel feeds the same all-zero words from
//      registers through the same `add(mul(...))` sequence (`mul` of the
//      zero element yields the zero word pattern, exactly as reading the
//      memset buffer does), so the memset itself can be skipped.
//
// The only observable difference is that the ping/pong scratch buffers never
// receive the stage-0/stage-1 intermediates. Those words are dead: every
// consumer of a fold round (retained-tree snapshot d2d, leaf hashing, the
// next round's folds, final-layer readback and query-time gathers) reads
// exactly `2^log_size` live words per coordinate.
//
// Eligibility is decided on the host (`prepared_fri.rs`, opt-in via
// `STWO_CUDA_FRI_FOLD_FUSED=1`): only complete three-fold rounds run here;
// the final partial round (fold_step < 3) fails closed to the per-fold
// kernels.

#include "fields.cuh"
#include "fri_utils.cuh"
#include "poly_utils.cuh"
#include "utils.cuh"

__global__ void fri_fold_fused3_kernel(
    m31 *domain,
    const uint32_t twiddle_offset_0,
    const uint32_t twiddle_offset_1,
    const uint32_t twiddle_offset_2,
    const uint32_t n,
    const uint32_t first_fold_is_circle,
    m31 **eval_values,
    const qm31 *alpha_device,
    m31 **folded_values
) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (n >> 3)) {
        return;
    }

    // Identical repeated-squaring chain to the per-fold kernels'
    // `alpha_squarings` loops (0, 1 and 2 squarings respectively).
    const qm31 alpha_0 = *alpha_device;
    const qm31 alpha_1 = mul(alpha_0, alpha_0);
    const qm31 alpha_2 = mul(alpha_1, alpha_1);

    // Stage 0 (size n -> n/2): circle-to-line on round 0, line fold otherwise.
    qm31 stage0[4];
#pragma unroll
    for (uint32_t k = 0; k < 4; ++k) {
        const uint32_t out_index = 4 * i + k;
        const qm31 f_x = getEvaluation(eval_values, 2 * out_index);
        const qm31 f_x_minus = getEvaluation(eval_values, 2 * out_index + 1);
        const qm31 f_0 = add(f_x, f_x_minus);
        const m31 x_inverse = first_fold_is_circle
            ? get_circle_twiddle(&domain[twiddle_offset_0], out_index)
            : domain[out_index + twiddle_offset_0];
        const qm31 f_1 = mul_by_scalar(sub(f_x, f_x_minus), x_inverse);
        qm31 f_prime = add(f_0, mul(alpha_0, f_1));
        if (first_fold_is_circle) {
            // Replicate the circle kernel's accumulator on its memset-zero
            // destination: previous_value words are all zero, and alpha_sq is
            // the same mul(alpha, alpha) expression as alpha_1 (0 squarings).
            const qm31 previous_value = {{0u, 0u}, {0u, 0u}};
            f_prime = add(mul(previous_value, alpha_1), f_prime);
        }
        stage0[k] = f_prime;
    }

    // Stage 1 (size n/2 -> n/4): line fold with alpha^2.
    qm31 stage1[2];
#pragma unroll
    for (uint32_t k = 0; k < 2; ++k) {
        const uint32_t out_index = 2 * i + k;
        const qm31 f_x = stage0[2 * k];
        const qm31 f_x_minus = stage0[2 * k + 1];
        const qm31 f_0 = add(f_x, f_x_minus);
        const m31 x_inverse = domain[out_index + twiddle_offset_1];
        const qm31 f_1 = mul_by_scalar(sub(f_x, f_x_minus), x_inverse);
        stage1[k] = add(f_0, mul(alpha_1, f_1));
    }

    // Stage 2 (size n/4 -> n/8): line fold with alpha^4. Only this result is
    // stored; it lands at the same address the third per-fold launch writes.
    const qm31 f_0 = add(stage1[0], stage1[1]);
    const m31 x_inverse = domain[i + twiddle_offset_2];
    const qm31 f_1 = mul_by_scalar(sub(stage1[0], stage1[1]), x_inverse);
    const qm31 f_prime = add(f_0, mul(alpha_2, f_1));
    folded_values[0][i] = f_prime.a.a;
    folded_values[1][i] = f_prime.a.b;
    folded_values[2][i] = f_prime.b.a;
    folded_values[3][i] = f_prime.b.b;
}

extern "C" int stwo_fri_fold_fused3_on(
    const uint32_t *gpu_domain,
    uint32_t twiddle_offset_0,
    uint32_t twiddle_offset_1,
    uint32_t twiddle_offset_2,
    uint32_t n,
    uint32_t first_fold_is_circle,
    uint32_t **eval_values,
    const qm31 *alpha,
    uint32_t **folded_values,
    void *stream
) {
    if (gpu_domain == nullptr || n < 8 || (n & (n - 1)) != 0 ||
        first_fold_is_circle > 1 || eval_values == nullptr || alpha == nullptr ||
        folded_values == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    constexpr int block_dim = 256;
    const int num_blocks = (n / 8 + block_dim - 1) / block_dim;
    fri_fold_fused3_kernel<<<num_blocks, block_dim, 0,
                             reinterpret_cast<cudaStream_t>(stream)>>>(
        const_cast<m31 *>(reinterpret_cast<const m31 *>(gpu_domain)),
        twiddle_offset_0,
        twiddle_offset_1,
        twiddle_offset_2,
        n,
        first_fold_is_circle,
        reinterpret_cast<m31 **>(eval_values),
        alpha,
        reinterpret_cast<m31 **>(folded_values)
    );
    return cudaGetLastError();
}
