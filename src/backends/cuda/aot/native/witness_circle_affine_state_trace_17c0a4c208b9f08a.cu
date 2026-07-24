// Generic circle-bit-reversed affine M31 state trace generation.
//
// The frontend supplies the state and recurrence recipe plus two resident
// destination slabs. This program owns no statement policy, allocation,
// transfer, synchronization, or fallback.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647ull

__device__ __forceinline__ unsigned stwo_m31_from_u64(u64 value) {
    u64 reduced = (value & STWO_M31_P) + (value >> 31u);
    reduced = (reduced & STWO_M31_P) + (reduced >> 31u);
    return reduced >= STWO_M31_P
        ? (unsigned)(reduced - STWO_M31_P)
        : (unsigned)reduced;
}

__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs,
    unsigned rhs) {
    const u64 sum = (u64)lhs + rhs;
    return (unsigned)(sum >= STWO_M31_P ? sum - STWO_M31_P : sum);
}

__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs,
    unsigned rhs) {
    return stwo_m31_from_u64((u64)lhs * rhs);
}

__device__ __forceinline__ unsigned stwo_reverse_low_bits(
    unsigned value,
    unsigned bit_count) {
    unsigned reversed = 0u;
    for (unsigned bit = 0u; bit < bit_count; ++bit) {
        reversed = (reversed << 1u) | (value & 1u);
        value >>= 1u;
    }
    return reversed;
}

__device__ __forceinline__ unsigned stwo_circle_to_coset_index(
    unsigned circle_index,
    unsigned row_count) {
    return circle_index < row_count / 2u
        ? circle_index * 2u
        : (row_count - 1u - circle_index) * 2u + 1u;
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_trace_circle_affine_state_slabs_v1_09db5e660658cf5e(
    unsigned *preprocessed_slab,
    u64 preprocessed_slab_words,
    u64 preprocessed_stride_words,
    unsigned *main_slab,
    u64 main_slab_words,
    u64 main_stride_words,
    unsigned row_count,
    unsigned log_n_rows,
    u64 initial_state0,
    u64 initial_state1,
    unsigned increment_coordinate,
    u64 increment_value,
    u64 indicator_first,
    u64 indicator_default) {
    const unsigned storage_row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (storage_row >= row_count) return;

    const u64 expected_rows =
        log_n_rows < 31u ? 1ull << log_n_rows : 0ull;
    if (preprocessed_slab == nullptr || main_slab == nullptr ||
        preprocessed_slab == main_slab ||
        log_n_rows == 0u || log_n_rows >= 31u ||
        (u64)row_count != expected_rows ||
        increment_coordinate >= 2u ||
        preprocessed_stride_words < expected_rows ||
        main_stride_words < expected_rows ||
        main_stride_words > (~0ull) / 2ull ||
        preprocessed_slab_words != preprocessed_stride_words ||
        main_slab_words != main_stride_words * 2ull) {
        return;
    }

    const unsigned circle_index =
        stwo_reverse_low_bits(storage_row, log_n_rows);
    const unsigned logical_row =
        stwo_circle_to_coset_index(circle_index, row_count);
    preprocessed_slab[storage_row] = stwo_m31_from_u64(
        storage_row == 0u ? indicator_first : indicator_default);

    unsigned state0 = stwo_m31_from_u64(initial_state0);
    unsigned state1 = stwo_m31_from_u64(initial_state1);
    const unsigned delta = stwo_m31_mul(
        stwo_m31_from_u64(logical_row),
        stwo_m31_from_u64(increment_value));
    if (increment_coordinate == 0u) {
        state0 = stwo_m31_add(state0, delta);
    } else {
        state1 = stwo_m31_add(state1, delta);
    }
    main_slab[storage_row] = state0;
    main_slab[main_stride_words + storage_row] = state1;
}
