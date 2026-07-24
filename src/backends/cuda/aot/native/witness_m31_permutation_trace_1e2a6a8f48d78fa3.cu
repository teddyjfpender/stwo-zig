// Generic 16-lane M31 algebraic-permutation trace generation.
//
// The proof frontend supplies statement geometry and the complete scalar
// recipe. This program owns no statement policy, allocation, transfer,
// synchronization, or fallback.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647ull
#define STWO_M31_STATE_WIDTH 16u

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

__device__ __forceinline__ unsigned stwo_m31_pow5(unsigned value) {
    const unsigned square = stwo_m31_mul(value, value);
    const unsigned fourth = stwo_m31_mul(square, square);
    return stwo_m31_mul(fourth, value);
}

__device__ __forceinline__ void stwo_m31_apply_m4(unsigned *values) {
    const unsigned t0 = stwo_m31_add(values[0], values[1]);
    const unsigned t02 = stwo_m31_add(t0, t0);
    const unsigned t1 = stwo_m31_add(values[2], values[3]);
    const unsigned t12 = stwo_m31_add(t1, t1);
    const unsigned t2 =
        stwo_m31_add(stwo_m31_add(values[1], values[1]), t1);
    const unsigned t3 =
        stwo_m31_add(stwo_m31_add(values[3], values[3]), t0);
    const unsigned t4 =
        stwo_m31_add(stwo_m31_add(t12, t12), t3);
    const unsigned t5 =
        stwo_m31_add(stwo_m31_add(t02, t02), t2);
    values[0] = stwo_m31_add(t3, t5);
    values[1] = t5;
    values[2] = stwo_m31_add(t2, t4);
    values[3] = t4;
}

__device__ __forceinline__ void stwo_m31_external_matrix(
    unsigned *state) {
    for (unsigned group = 0u; group < 4u; ++group) {
        stwo_m31_apply_m4(state + group * 4u);
    }
    for (unsigned lane = 0u; lane < 4u; ++lane) {
        unsigned sum = state[lane];
        sum = stwo_m31_add(sum, state[lane + 4u]);
        sum = stwo_m31_add(sum, state[lane + 8u]);
        sum = stwo_m31_add(sum, state[lane + 12u]);
        for (unsigned group = 0u; group < 4u; ++group) {
            const unsigned index = group * 4u + lane;
            state[index] = stwo_m31_add(state[index], sum);
        }
    }
}

__device__ __forceinline__ void stwo_m31_internal_matrix(
    unsigned *state) {
    unsigned sum = state[0];
    for (unsigned lane = 1u; lane < STWO_M31_STATE_WIDTH; ++lane) {
        sum = stwo_m31_add(sum, state[lane]);
    }
    unsigned coefficient = 2u;
    for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
        state[lane] =
            stwo_m31_add(stwo_m31_mul(state[lane], coefficient), sum);
        coefficient = stwo_m31_add(coefficient, coefficient);
    }
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_trace_m31_permutation_slab_v1_81b27c7c25216799(
    unsigned *trace_slab,
    u64 trace_slab_words,
    u64 column_stride_words,
    unsigned row_count,
    unsigned log_n_rows,
    unsigned replication_count,
    unsigned half_full_rounds,
    unsigned partial_rounds,
    u64 initial_row_stride,
    u64 initial_rep_stride,
    u64 external_constant_base,
    u64 external_round_stride,
    u64 internal_constant_base,
    u64 internal_round_stride) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;

    const u64 columns_per_rep =
        (u64)STWO_M31_STATE_WIDTH * (1ull + 2ull * half_full_rounds) +
        partial_rounds;
    const u64 column_count = (u64)replication_count * columns_per_rep;
    const u64 expected_rows =
        log_n_rows < 31u ? 1ull << log_n_rows : 0ull;
    const u64 maximum_row_base =
        expected_rows == 0ull ? ~0ull :
        (expected_rows - 1ull) * initial_row_stride;
    if (trace_slab == nullptr || log_n_rows >= 31u ||
        (u64)row_count != expected_rows ||
        replication_count == 0u || replication_count > 256u ||
        half_full_rounds == 0u || half_full_rounds > 64u ||
        partial_rounds == 0u || partial_rounds > 256u ||
        column_count == 0ull || column_count > 0xffffffffull ||
        column_stride_words < expected_rows ||
        column_stride_words > (~0ull) / column_count ||
        trace_slab_words != column_stride_words * column_count ||
        initial_row_stride == 0ull || initial_rep_stride == 0ull ||
        (expected_rows - 1ull) > (~0ull) / initial_row_stride ||
        maximum_row_base > ~0ull - (STWO_M31_STATE_WIDTH - 1u) ||
        (u64)(replication_count - 1u) >
            (~0ull - maximum_row_base - (STWO_M31_STATE_WIDTH - 1u)) /
            initial_rep_stride) {
        return;
    }

    u64 column = 0ull;
    for (unsigned rep = 0u; rep < replication_count; ++rep) {
        unsigned state[STWO_M31_STATE_WIDTH];
        const u64 initial_base =
            (u64)row * initial_row_stride + (u64)rep * initial_rep_stride;
        for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
            state[lane] = stwo_m31_from_u64(initial_base + lane);
            trace_slab[column * column_stride_words + row] = state[lane];
            ++column;
        }

        for (unsigned round = 0u; round < half_full_rounds; ++round) {
            for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
                const u64 round_constant =
                    external_constant_base +
                    (u64)round * external_round_stride +
                    lane;
                state[lane] =
                    stwo_m31_add(state[lane], stwo_m31_from_u64(round_constant));
            }
            stwo_m31_external_matrix(state);
            for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
                state[lane] = stwo_m31_pow5(state[lane]);
                trace_slab[column * column_stride_words + row] = state[lane];
                ++column;
            }
        }

        for (unsigned round = 0u; round < partial_rounds; ++round) {
            const u64 round_constant =
                internal_constant_base + (u64)round * internal_round_stride;
            state[0] =
                stwo_m31_add(state[0], stwo_m31_from_u64(round_constant));
            stwo_m31_internal_matrix(state);
            state[0] = stwo_m31_pow5(state[0]);
            trace_slab[column * column_stride_words + row] = state[0];
            ++column;
        }

        for (unsigned half_round = 0u;
             half_round < half_full_rounds;
             ++half_round) {
            const unsigned round = half_round + half_full_rounds;
            for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
                const u64 round_constant =
                    external_constant_base +
                    (u64)round * external_round_stride +
                    lane;
                state[lane] =
                    stwo_m31_add(state[lane], stwo_m31_from_u64(round_constant));
            }
            stwo_m31_external_matrix(state);
            for (unsigned lane = 0u; lane < STWO_M31_STATE_WIDTH; ++lane) {
                state[lane] = stwo_m31_pow5(state[lane]);
                trace_slab[column * column_stride_words + row] = state[lane];
                ++column;
            }
        }
    }
}
