#include "composition.cuh"

#include <cuda_runtime.h>

namespace {

__global__ void generate_descending_powers(
    const qm31 *random_coefficient,
    qm31 *powers,
    uint32_t count
) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count) {
        // DomainEvaluationAccumulator first consumes alpha^(N - 1), then
        // alpha^(N - 2), ... across components in protocol order.
        powers[index] = pow(*random_coefficient, uint64_t(count - 1 - index));
    }
}

__global__ void lift_accumulate_coordinates(
    const uint32_t *previous_coordinates,
    uint32_t previous_size,
    uint32_t *current_coordinates,
    uint32_t current_size,
    uint32_t log_ratio
) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= current_size) return;

    // This is exactly CpuBackend::lift_and_accumulate's bit-reversed circle
    // lift. The low bit identifies the circle half and the remaining bits are
    // repeated over the larger domain.
    const uint32_t lifted_index =
        (index >> (log_ratio + 1) << 1) + (index & 1u);
    #pragma unroll
    for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        const uint32_t previous =
            previous_coordinates[coordinate * previous_size + lifted_index];
        uint32_t &current = current_coordinates[coordinate * current_size + index];
        current = add(current, previous);
    }
}

__global__ void materialize_ext_params(
    qm31 *const *destinations,
    const uint32_t *source_kinds,
    const uint32_t *source_indices,
    const m31 *scales,
    uint32_t count,
    const qm31 *z,
    const qm31 *alpha_powers,
    const qm31 *const *claimed_sums
) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    const uint32_t kind = source_kinds[index];
    const uint32_t source = source_indices[index];
    qm31 value;
    if (kind == 0) {
        value = *z;
    } else if (kind == 1) {
        value = alpha_powers[source];
    } else {
        value = *claimed_sums[source];
    }
    *destinations[index] = mul_by_scalar(value, scales[index]);
}

}  // namespace

extern "C" int stwo_composition_generate_descending_powers_on(
    const qm31 *random_coefficient,
    qm31 *powers,
    uint32_t count,
    void *stream
) {
    if (random_coefficient == nullptr || powers == nullptr || stream == nullptr || count == 0) {
        return cudaErrorInvalidValue;
    }
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (count + block_size - 1) / block_size;
    generate_descending_powers<<<blocks, block_size, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        random_coefficient, powers, count);
    return cudaGetLastError();
}

extern "C" int stwo_composition_lift_accumulate_on(
    const uint32_t *previous_coordinates,
    uint32_t previous_log_size,
    uint32_t *current_coordinates,
    uint32_t current_log_size,
    void *stream
) {
    if (previous_coordinates == nullptr || current_coordinates == nullptr || stream == nullptr ||
        previous_log_size == 0 || current_log_size <= previous_log_size ||
        current_log_size > 30) {
        return cudaErrorInvalidValue;
    }
    const uint32_t previous_size = 1u << previous_log_size;
    const uint32_t current_size = 1u << current_log_size;
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (current_size + block_size - 1) / block_size;
    lift_accumulate_coordinates<<<
        blocks, block_size, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        previous_coordinates,
        previous_size,
        current_coordinates,
        current_size,
        current_log_size - previous_log_size);
    return cudaGetLastError();
}

extern "C" int stwo_composition_materialize_ext_params_on(
    qm31 *const *destinations,
    const uint32_t *source_kinds,
    const uint32_t *source_indices,
    const m31 *scales,
    uint32_t count,
    const qm31 *z,
    const qm31 *alpha_powers,
    uint32_t alpha_power_count,
    const qm31 *const *claimed_sums,
    uint32_t claimed_sum_count,
    void *stream
) {
    if (destinations == nullptr || source_kinds == nullptr || source_indices == nullptr ||
        scales == nullptr || count == 0 || z == nullptr || alpha_powers == nullptr ||
        alpha_power_count == 0 || (claimed_sum_count != 0 && claimed_sums == nullptr) ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    // Source bounds are immutable setup data; validate once before launch.
    // Copying them to host here would violate capture, so the prepared Rust
    // planner proves every index is within these explicit counts.
    (void)claimed_sum_count;
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (count + block_size - 1) / block_size;
    materialize_ext_params<<<blocks, block_size, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        destinations,
        source_kinds,
        source_indices,
        scales,
        count,
        z,
        alpha_powers,
        claimed_sums);
    return cudaGetLastError();
}
