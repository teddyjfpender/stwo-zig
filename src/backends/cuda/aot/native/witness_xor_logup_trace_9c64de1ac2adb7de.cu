// Exact Native XOR truth-table witness in circle-domain bit-reversed storage.
//
// One lane owns one stored row. Truth-table multiplicities are closed-form,
// so witness construction has no scan, allocation, transfer, or fallback.

#include <cstdint>

using u64 = unsigned long long;

__device__ __forceinline__ std::uint32_t reverse_bits(
    std::uint32_t value,
    std::uint32_t bits) {
    return bits == 0u ? value : __brev(value) >> (32u - bits);
}

__device__ __forceinline__ std::uint32_t stored_to_coset_row(
    std::uint32_t stored,
    std::uint32_t log_size) {
    const std::uint32_t rows = 1u << log_size;
    const std::uint32_t circle = reverse_bits(stored, log_size);
    if (circle < rows / 2u) return 2u * circle;
    return 2u * (rows - 1u - circle) + 1u;
}

__device__ __forceinline__ std::uint32_t selected_count_for_a(
    std::uint32_t a,
    std::uint32_t row_count,
    std::uint32_t log_step,
    std::uint32_t selected_offset) {
    if (log_step == 0u) return row_count / 2u;
    if (log_step == 1u) return row_count / 4u;
    const std::uint32_t selected_a = (selected_offset >> 1u) & 1u;
    return a == selected_a ? row_count >> log_step : 0u;
}

extern "C" __global__ void __launch_bounds__(128)
stwo_native_trace_xor_logup_slabs_v1_77dc01e39a2d5eb5(
    std::uint32_t *preprocessed_slab,
    u64 preprocessed_slab_words,
    u64 preprocessed_stride_words,
    std::uint32_t *main_slab,
    u64 main_slab_words,
    u64 main_stride_words,
    std::uint32_t *relation_source_slab,
    u64 relation_source_slab_words,
    u64 relation_source_stride_words,
    std::uint32_t row_count,
    std::uint32_t log_size,
    std::uint32_t log_step,
    u64 offset) {
    const std::uint32_t stored =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (stored >= row_count) return;
    if (preprocessed_slab == nullptr || main_slab == nullptr ||
        relation_source_slab == nullptr ||
        log_size < 2u || log_size >= 30u || log_step > log_size) {
        return;
    }
    const u64 expected_rows = 1ull << log_size;
    const u64 required_preprocessed =
        6ull * preprocessed_stride_words + expected_rows;
    const u64 required_main =
        3ull * main_stride_words + expected_rows;
    const u64 required_relation =
        6ull * relation_source_stride_words + expected_rows;
    if (static_cast<u64>(row_count) != expected_rows ||
        preprocessed_stride_words < expected_rows ||
        main_stride_words < expected_rows ||
        relation_source_stride_words < expected_rows ||
        required_preprocessed > preprocessed_slab_words ||
        required_main > main_slab_words ||
        required_relation > relation_source_slab_words) {
        return;
    }

    const std::uint32_t row = stored_to_coset_row(stored, log_size);
    const std::uint32_t step = 1u << log_step;
    const std::uint32_t selected_offset =
        static_cast<std::uint32_t>(offset & (step - 1u));
    const std::uint32_t a = (row >> 1u) & 1u;
    const std::uint32_t b =
        (row & (step - 1u)) == selected_offset ? 1u : 0u;
    const std::uint32_t c = a ^ b;
    const std::uint32_t table_selector = row < 4u ? 1u : 0u;
    const std::uint32_t table_a =
        table_selector == 0u ? 0u : (row >> 1u) & 1u;
    const std::uint32_t table_b =
        table_selector == 0u ? 0u : row & 1u;
    const std::uint32_t table_c = table_a ^ table_b;

    preprocessed_slab[stored] = row == 0u ? 1u : 0u;
    preprocessed_slab[preprocessed_stride_words + stored] = b;
    preprocessed_slab[2ull * preprocessed_stride_words + stored] = a;
    preprocessed_slab[3ull * preprocessed_stride_words + stored] =
        table_selector;
    preprocessed_slab[4ull * preprocessed_stride_words + stored] = table_a;
    preprocessed_slab[5ull * preprocessed_stride_words + stored] = table_b;
    preprocessed_slab[6ull * preprocessed_stride_words + stored] = table_c;

    std::uint32_t multiplicity = 0u;
    if (table_selector != 0u) {
        const std::uint32_t selected = selected_count_for_a(
            table_a,
            row_count,
            log_step,
            selected_offset);
        multiplicity = table_b == 0u
            ? row_count / 2u - selected
            : selected;
    }
    main_slab[stored] = a;
    main_slab[main_stride_words + stored] = b;
    main_slab[2ull * main_stride_words + stored] = c;
    main_slab[3ull * main_stride_words + stored] = multiplicity;

    // The commitment IFFT overwrites the base-tree input slabs. Preserve the
    // exact values consumed by the post-commit LogUp relation in its own
    // immutable arena range.
    relation_source_slab[stored] = table_a;
    relation_source_slab[relation_source_stride_words + stored] = table_b;
    relation_source_slab[2ull * relation_source_stride_words + stored] =
        table_c;
    relation_source_slab[3ull * relation_source_stride_words + stored] =
        multiplicity;
    relation_source_slab[4ull * relation_source_stride_words + stored] = a;
    relation_source_slab[5ull * relation_source_stride_words + stored] = b;
    relation_source_slab[6ull * relation_source_stride_words + stored] = c;
}
