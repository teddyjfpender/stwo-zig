// Statement-independent constant-QM31 composition over a structural domain.
//
// The caller owns all memory and synchronization. Statement and challenge
// slices bind the launch to resident proof inputs but are deliberately not
// interpreted: the admitted AIR supplies the already-evaluated constant.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

struct StwoCudaQm31 {
    unsigned a, b, c, d;
};

extern "C" __global__ void __launch_bounds__(128)
stwo_native_constraint_constant_qm31_slab_v1_578d333ea30082f5(
    unsigned component_index,
    unsigned component_count,
    unsigned evaluation_log_size,
    unsigned trace_log_size,
    unsigned preprocessed_column_count,
    unsigned main_column_count,
    const unsigned *statement_words,
    u64 statement_word_count,
    const unsigned *challenge_words,
    u64 challenge_word_count,
    StwoCudaQm31 constant_composition,
    unsigned *coordinate_slab,
    u64 coordinate_slab_words,
    u64 coordinate_stride_words,
    unsigned row_count) {
    const unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_index >= row_count) return;

    const u64 total_columns =
        (u64)preprocessed_column_count + (u64)main_column_count;
    if (component_count == 0u || component_index >= component_count ||
        evaluation_log_size >= 31u ||
        trace_log_size > evaluation_log_size ||
        total_columns == 0ull || total_columns > 0xffffffffull ||
        ((statement_word_count == 0ull) != (statement_words == nullptr)) ||
        ((challenge_word_count == 0ull) != (challenge_words == nullptr)) ||
        constant_composition.a >= STWO_M31_P ||
        constant_composition.b >= STWO_M31_P ||
        constant_composition.c >= STWO_M31_P ||
        constant_composition.d >= STWO_M31_P ||
        coordinate_slab == nullptr) {
        return;
    }

    const u64 expected_rows = 1ull << evaluation_log_size;
    if (coordinate_stride_words >
        (~0ull - expected_rows) / 3ull) {
        return;
    }
    const u64 required_coordinate_words =
        3ull * coordinate_stride_words + expected_rows;
    if ((u64)row_count != expected_rows ||
        coordinate_stride_words < expected_rows ||
        required_coordinate_words > coordinate_slab_words) {
        return;
    }

    coordinate_slab[row_index] = constant_composition.a;
    coordinate_slab[coordinate_stride_words + row_index] =
        constant_composition.b;
    coordinate_slab[2ull * coordinate_stride_words + row_index] =
        constant_composition.c;
    coordinate_slab[3ull * coordinate_stride_words + row_index] =
        constant_composition.d;
}
