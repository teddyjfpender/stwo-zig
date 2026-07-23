// Device-side logup interaction-trace finalize (the witness-on-GPU W1 lane).
//
// The host writes raw (numerator, denominator) pairs per logup column; everything
// from the denominator inversion onward happens here: batched inversion, the
// fraction chain across columns, the claimed-sum reduction, the cumsum shift, and
// (via the existing inclusive_prefix_sum lane) the per-coordinate prefix sums.
// Values are exactly the SIMD reference's: field adds are associative/commutative
// (any reduction/scan order yields the same element) and inverses are unique. The
// byte-equality gate is the finalize differential in stwo-backend-cuda's tests.
//
// Layouts: numerator coordinates arrive as 4 contiguous m31 columns (the SIMD
// coordinate layout uploads as-is). The denominator arrives in the SIMD
// PackedSecureField lane layout — per 16-element block: 16 a-words, 16 b-words,
// 16 c-words, 16 d-words — and is de-interleaved on device into element-major qm31
// for the shared batch-inversion kernel.

#include "batch_inverse.cuh"
#include "fields.cuh"
#include "utils.cuh"

namespace {

constexpr uint32_t LOGUP_BLOCK_DIM = 256;
constexpr uint32_t LANE_BLOCK = 16;  // N_LANES of the SIMD backend's packed fields.

// Packed-lane SecureColumn -> element-major qm31.
__global__ void deinterleave_packed_qm31_kernel(
    const m31 *packed,
    qm31 *out,
    uint32_t size
) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= size) {
        return;
    }
    uint32_t base = (i / LANE_BLOCK) * (4 * LANE_BLOCK) + (i % LANE_BLOCK);
    out[i] = qm31{
        cm31{packed[base], packed[base + LANE_BLOCK]},
        cm31{packed[base + 2 * LANE_BLOCK], packed[base + 3 * LANE_BLOCK]},
    };
}

// value = numerator * denom_inv + prev (prev nullable for the first column),
// written back into the numerator coordinate columns in place.
__global__ void logup_fraction_chain_kernel(
    m31 *num0, m31 *num1, m31 *num2, m31 *num3,
    const qm31 *denom_inv,
    const m31 *prev0, const m31 *prev1, const m31 *prev2, const m31 *prev3,
    uint32_t size
) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= size) {
        return;
    }
    qm31 numerator = qm31{cm31{num0[i], num1[i]}, cm31{num2[i], num3[i]}};
    qm31 value = mul(numerator, denom_inv[i]);
    if (prev0 != nullptr) {
        qm31 prev = qm31{cm31{prev0[i], prev1[i]}, cm31{prev2[i], prev3[i]}};
        value = add(value, prev);
    }
    num0[i] = value.a.a;
    num1[i] = value.a.b;
    num2[i] = value.b.a;
    num3[i] = value.b.b;
}

// Block-level m31 sum reduction (modular adds; order-independent by field axioms).
__global__ void sum_m31_partial_kernel(const m31 *values, uint32_t size, m31 *partials) {
    extern __shared__ m31 shared[];
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    shared[threadIdx.x] = i < size ? values[i] : 0;
    __syncthreads();
    for (uint32_t stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        partials[blockIdx.x] = shared[0];
    }
}

m31 sum_m31_column(const m31 *values, uint32_t size) {
    uint32_t num_blocks = (size + LOGUP_BLOCK_DIM - 1) / LOGUP_BLOCK_DIM;
    m31 *current = cuda_proving_malloc<m31>(num_blocks);
    sum_m31_partial_kernel<<<num_blocks, LOGUP_BLOCK_DIM, sizeof(m31) * LOGUP_BLOCK_DIM>>>(
        values, size, current);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    uint32_t current_size = num_blocks;
    while (current_size > 1) {
        uint32_t next_size = (current_size + LOGUP_BLOCK_DIM - 1) / LOGUP_BLOCK_DIM;
        m31 *next = cuda_proving_malloc<m31>(next_size);
        sum_m31_partial_kernel<<<next_size, LOGUP_BLOCK_DIM, sizeof(m31) * LOGUP_BLOCK_DIM>>>(
            current, current_size, next);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        cuda_proving_free(current);
        current = next;
        current_size = next_size;
    }
    m31 result = 0;
    // Synchronous D2H: the host-read fence.
    cuda_mem_copy_device_to_host<m31>(current, &result, 1);
    cuda_proving_free(current);
    return result;
}

__global__ void sub_broadcast_m31_kernel(m31 *values, m31 shift, uint32_t size) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < size) {
        values[i] = sub(values[i], shift);
    }
}

}  // namespace

// Element-major variant: denominators already on device in qm31 element order
// (device-generated witness lanes) — no de-interleave, no H2D.
extern "C" void logup_fraction_chain_dense(
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3,
    const uint32_t *denoms_dense,
    const uint32_t *prev0, const uint32_t *prev1,
    const uint32_t *prev2, const uint32_t *prev3,
    uint32_t size
) {
    qm31 *inverses = cuda_proving_malloc<qm31>(size);
    batch_inverse_secure_field(
        const_cast<qm31 *>(reinterpret_cast<const qm31 *>(denoms_dense)), inverses, size);
    uint32_t num_blocks = (size + LOGUP_BLOCK_DIM - 1) / LOGUP_BLOCK_DIM;
    logup_fraction_chain_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(
        num0, num1, num2, num3,
        inverses,
        prev0, prev1, prev2, prev3,
        size);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    cuda_proving_free(inverses);
}

// One logup column's chain step: de-interleave + batch-invert the packed-lane
// denominators, then value = num * inv + prev in place over the numerator coords.
extern "C" void logup_fraction_chain(
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3,
    const uint32_t *denom_packed,
    const uint32_t *prev0, const uint32_t *prev1,
    const uint32_t *prev2, const uint32_t *prev3,
    uint32_t size
) {
    qm31 *denoms = cuda_proving_malloc<qm31>(size);
    qm31 *inverses = cuda_proving_malloc<qm31>(size);
    uint32_t num_blocks = (size + LOGUP_BLOCK_DIM - 1) / LOGUP_BLOCK_DIM;
    deinterleave_packed_qm31_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(
        reinterpret_cast<const m31 *>(denom_packed), denoms, size);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    batch_inverse_secure_field(denoms, inverses, size);
    logup_fraction_chain_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(
        num0, num1, num2, num3,
        inverses,
        prev0, prev1, prev2, prev3,
        size);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    cuda_proving_free(denoms);
    cuda_proving_free(inverses);
}

// Sums the 4 coordinate columns of the last logup column (the claimed sum) and
// returns it to the host (16-byte fenced readback).
extern "C" qm31 logup_sum_secure_coords(
    const uint32_t *c0, const uint32_t *c1, const uint32_t *c2, const uint32_t *c3,
    uint32_t size
) {
    return qm31{
        cm31{sum_m31_column(c0, size), sum_m31_column(c1, size)},
        cm31{sum_m31_column(c2, size), sum_m31_column(c3, size)},
    };
}

// Subtracts the broadcast cumsum shift from each coordinate column in place.
extern "C" void logup_shift_secure_coords(
    uint32_t *c0, uint32_t *c1, uint32_t *c2, uint32_t *c3,
    qm31 shift,
    uint32_t size
) {
    uint32_t num_blocks = (size + LOGUP_BLOCK_DIM - 1) / LOGUP_BLOCK_DIM;
    sub_broadcast_m31_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(c0, shift.a.a, size);
    sub_broadcast_m31_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(c1, shift.a.b, size);
    sub_broadcast_m31_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(c2, shift.b.a, size);
    sub_broadcast_m31_kernel<<<num_blocks, LOGUP_BLOCK_DIM>>>(c3, shift.b.b, size);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}
