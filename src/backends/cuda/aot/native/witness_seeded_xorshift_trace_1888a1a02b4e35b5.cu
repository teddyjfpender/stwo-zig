// Generic seeded-xorshift column generation over one resident M31 slab.
//
// The proof frontend supplies the complete recipe. This program owns no
// statement policy, allocation, transfer, synchronization, or fallback.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647ull

__device__ __forceinline__ unsigned stwo_m31_from_u64(u64 value) {
    u64 reduced = (value & STWO_M31_P) + (value >> 31u);
    reduced = (reduced & STWO_M31_P) + (reduced >> 31u);
    return reduced >= STWO_M31_P
        ? (unsigned)(reduced - STWO_M31_P)
        : (unsigned)reduced;
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_trace_seeded_xorshift_slab_v1_21cc1d6d9728809e(
    unsigned *trace_slab,
    u64 trace_slab_words,
    u64 column_stride_words,
    unsigned row_count,
    unsigned log_n_rows,
    unsigned group_count,
    unsigned columns_per_group,
    u64 seed_offset,
    unsigned left_shift,
    unsigned right_shift,
    unsigned final_left_shift,
    u64 group_mix,
    u64 item_mix) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;

    const u64 column_count = (u64)group_count * columns_per_group;
    const u64 expected_rows =
        log_n_rows < 31u ? 1ull << log_n_rows : 0ull;
    if (trace_slab == nullptr || log_n_rows == 0u || log_n_rows >= 31u ||
        (u64)row_count != expected_rows ||
        group_count == 0u || columns_per_group == 0u ||
        column_count == 0ull || column_count > 0xffffffffull ||
        column_stride_words < expected_rows ||
        column_stride_words > (~0ull) / column_count ||
        trace_slab_words != column_stride_words * column_count ||
        seed_offset > (~0ull) - (expected_rows - 1ull) ||
        left_shift == 0u || left_shift >= 64u ||
        right_shift == 0u || right_shift >= 64u ||
        final_left_shift == 0u || final_left_shift >= 64u) {
        return;
    }

    u64 seed = (u64)row + seed_offset;
    u64 column = 0ull;
    for (unsigned group = 0u; group < group_count; ++group) {
        for (unsigned item = 0u; item < columns_per_group; ++item) {
            u64 x1 = seed ^ (seed << left_shift);
            u64 x2 = x1 ^ (x1 >> right_shift);
            seed = x2 ^ (x2 << final_left_shift);
            const u64 mixed =
                seed ^
                ((u64)group * group_mix) ^
                ((u64)(item + 1u) * item_mix);
            trace_slab[column * column_stride_words + row] =
                stwo_m31_from_u64(mixed);
            ++column;
        }
    }
}
