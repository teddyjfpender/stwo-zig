// State Machine composition is the sum of its two transcript-derived claims.

#include <cstdint>

using u64 = unsigned long long;

constexpr std::uint32_t kM31Prime = 2147483647u;

struct StwoCudaQm31 {
    std::uint32_t a, b, c, d;
};

__device__ __forceinline__ std::uint32_t add_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    const u64 sum = static_cast<u64>(lhs) + static_cast<u64>(rhs);
    return static_cast<std::uint32_t>(
        sum < kM31Prime ? sum : sum - kM31Prime);
}

extern "C" __global__ void __launch_bounds__(128)
stwo_native_constraint_state_machine_slab_v1_199a83f08c52455b(
    std::uint32_t component_index,
    std::uint32_t component_count,
    std::uint32_t evaluation_log_size,
    std::uint32_t trace_log_size,
    std::uint32_t preprocessed_column_count,
    std::uint32_t main_column_count,
    const std::uint32_t *statement_words,
    u64 statement_word_count,
    const std::uint32_t *challenge_words,
    u64 challenge_word_count,
    StwoCudaQm31,
    std::uint32_t *coordinate_slab,
    u64 coordinate_slab_words,
    u64 coordinate_stride_words,
    std::uint32_t row_count) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    const u64 expected_rows = 1ull << evaluation_log_size;
    if (component_count != 1u || component_index != 0u ||
        evaluation_log_size >= 31u ||
        trace_log_size > evaluation_log_size ||
        preprocessed_column_count != 1u || main_column_count != 2u ||
        statement_words == nullptr || statement_word_count != 14u ||
        challenge_words == nullptr || challenge_word_count != 4u ||
        coordinate_slab == nullptr ||
        static_cast<u64>(row_count) != expected_rows ||
        coordinate_stride_words < expected_rows ||
        3ull * coordinate_stride_words + expected_rows >
            coordinate_slab_words) {
        return;
    }
#pragma unroll
    for (std::uint32_t coordinate = 0; coordinate < 4u; ++coordinate) {
        const std::uint32_t lhs = statement_words[6u + coordinate];
        const std::uint32_t rhs = statement_words[10u + coordinate];
        if (lhs >= kM31Prime || rhs >= kM31Prime) return;
        coordinate_slab[
            static_cast<u64>(coordinate) * coordinate_stride_words + row] =
            add_m31(lhs, rhs);
    }
}
