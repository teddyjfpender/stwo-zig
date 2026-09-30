// Plain and domain-prefixed Blake2s protocols share the same kernels. The product ABI
// replaces its pointer tables with a checked resident slab on the proof stream.

#include "blake2s_protocol.cuh"
#include "progressive_scalar.cuh"
#include "resident_layout.cuh"

#include <cuda_runtime_api.h>

#include <stdint.h>

namespace stwo::cuda::blake2s {

#define STWO_LOAD_PROGRESSIVE(state) \
    uint32_t h0 = state.hash[0];      \
    uint32_t h1 = state.hash[1];      \
    uint32_t h2 = state.hash[2];      \
    uint32_t h3 = state.hash[3];      \
    uint32_t h4 = state.hash[4];      \
    uint32_t h5 = state.hash[5];      \
    uint32_t h6 = state.hash[6];      \
    uint32_t h7 = state.hash[7];      \
    uint32_t p0 = state.pending[0];   \
    uint32_t p1 = state.pending[1];   \
    uint32_t p2 = state.pending[2];   \
    uint32_t p3 = state.pending[3];   \
    uint32_t p4 = state.pending[4];   \
    uint32_t p5 = state.pending[5];   \
    uint32_t p6 = state.pending[6];   \
    uint32_t p7 = state.pending[7];   \
    uint32_t p8 = state.pending[8];   \
    uint32_t p9 = state.pending[9];   \
    uint32_t p10 = state.pending[10]; \
    uint32_t p11 = state.pending[11]; \
    uint32_t p12 = state.pending[12]; \
    uint32_t p13 = state.pending[13]; \
    uint32_t p14 = state.pending[14]; \
    uint32_t p15 = state.pending[15]

#define STWO_COMPRESS_PROGRESSIVE(counter, last)                          \
    progressive_compress(                                                 \
        h0,h1,h2,h3,h4,h5,h6,h7,                                         \
        p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,          \
        counter,last)

#define STWO_STORE_PROGRESSIVE(state) \
    state.hash[0] = h0;               \
    state.hash[1] = h1;               \
    state.hash[2] = h2;               \
    state.hash[3] = h3;               \
    state.hash[4] = h4;               \
    state.hash[5] = h5;               \
    state.hash[6] = h6;               \
    state.hash[7] = h7;               \
    state.pending[0] = p0;            \
    state.pending[1] = p1;            \
    state.pending[2] = p2;            \
    state.pending[3] = p3;            \
    state.pending[4] = p4;            \
    state.pending[5] = p5;            \
    state.pending[6] = p6;            \
    state.pending[7] = p7;            \
    state.pending[8] = p8;            \
    state.pending[9] = p9;            \
    state.pending[10] = p10;          \
    state.pending[11] = p11;          \
    state.pending[12] = p12;          \
    state.pending[13] = p13;          \
    state.pending[14] = p14;          \
    state.pending[15] = p15

__host__ __device__ constexpr uint32_t pending_words(
    uint32_t absorbed_columns) {
    return absorbed_columns == 0 ? 0 : ((absorbed_columns - 1) & 15u) + 1;
}

template <bool Prefixed>
__global__ void progressive_init_kernel(
    uint32_t size,
    ProgressiveState *states) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    ProgressiveState state{};
    initialize_leaf_for<Prefixed>(state.hash);
    states[row] = state;
}

template <bool Prefixed>
__global__ void progressive_absorb_kernel(
    uint32_t size,
    uint32_t column_count,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    ProgressiveState *states) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    ProgressiveState &state = states[row];
    STWO_LOAD_PROGRESSIVE(state);
    uint32_t pending = pending_words(absorbed_before);
    uint64_t compressed_bytes = (Prefixed ? kDomainPrefixBytes : 0) +
        static_cast<uint64_t>(absorbed_before - pending) * sizeof(uint32_t);
    for (uint32_t column = 0; column < column_count; ++column) {
        if (pending == 16) {
            compressed_bytes += 64;
            STWO_COMPRESS_PROGRESSIVE(compressed_bytes, 0);
            pending = 0;
        }
        const uint32_t word =
            columns[static_cast<size_t>(column) * column_stride_words + row];
        switch (pending++) {
            case 0: p0 = word; break;
            case 1: p1 = word; break;
            case 2: p2 = word; break;
            case 3: p3 = word; break;
            case 4: p4 = word; break;
            case 5: p5 = word; break;
            case 6: p6 = word; break;
            case 7: p7 = word; break;
            case 8: p8 = word; break;
            case 9: p9 = word; break;
            case 10: p10 = word; break;
            case 11: p11 = word; break;
            case 12: p12 = word; break;
            case 13: p13 = word; break;
            case 14: p14 = word; break;
            default: p15 = word; break;
        }
    }
    STWO_STORE_PROGRESSIVE(state);
}

__device__ __forceinline__ uint32_t lifted_column_index(
    uint32_t lifted_index,
    uint32_t log_ratio) {
    if (log_ratio == 0) return lifted_index;
    return ((lifted_index >> (log_ratio + 1u)) << 1u) |
        (lifted_index & 1u);
}

template <bool Prefixed>
__global__ void progressive_absorb_lifted_kernel(
    uint32_t size,
    uint32_t column_count,
    uint32_t absorbed_before,
    uint32_t log_ratio,
    const uint32_t *columns,
    size_t column_stride_words,
    ProgressiveState *states) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    ProgressiveState &state = states[row];
    STWO_LOAD_PROGRESSIVE(state);
    uint32_t pending = pending_words(absorbed_before);
    uint64_t compressed_bytes = (Prefixed ? kDomainPrefixBytes : 0) +
        static_cast<uint64_t>(absorbed_before - pending) * sizeof(uint32_t);
    const uint32_t source_row = lifted_column_index(row, log_ratio);
    for (uint32_t column = 0; column < column_count; ++column) {
        if (pending == 16) {
            compressed_bytes += 64;
            STWO_COMPRESS_PROGRESSIVE(compressed_bytes, 0);
            pending = 0;
        }
        const uint32_t word = columns[
            static_cast<size_t>(column) * column_stride_words + source_row];
        switch (pending++) {
            case 0: p0 = word; break;
            case 1: p1 = word; break;
            case 2: p2 = word; break;
            case 3: p3 = word; break;
            case 4: p4 = word; break;
            case 5: p5 = word; break;
            case 6: p6 = word; break;
            case 7: p7 = word; break;
            case 8: p8 = word; break;
            case 9: p9 = word; break;
            case 10: p10 = word; break;
            case 11: p11 = word; break;
            case 12: p12 = word; break;
            case 13: p13 = word; break;
            case 14: p14 = word; break;
            default: p15 = word; break;
        }
    }
    STWO_STORE_PROGRESSIVE(state);
}

template <bool Prefixed>
__global__ void progressive_finalize_kernel(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveState *states,
    Hash *result) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    const ProgressiveState &state = states[row];
    STWO_LOAD_PROGRESSIVE(state);
    const uint32_t pending = pending_words(absorbed_columns);
    if (pending < 1) p0 = 0;
    if (pending < 2) p1 = 0;
    if (pending < 3) p2 = 0;
    if (pending < 4) p3 = 0;
    if (pending < 5) p4 = 0;
    if (pending < 6) p5 = 0;
    if (pending < 7) p6 = 0;
    if (pending < 8) p7 = 0;
    if (pending < 9) p8 = 0;
    if (pending < 10) p9 = 0;
    if (pending < 11) p10 = 0;
    if (pending < 12) p11 = 0;
    if (pending < 13) p12 = 0;
    if (pending < 14) p13 = 0;
    if (pending < 15) p14 = 0;
    if (pending < 16) p15 = 0;
    STWO_COMPRESS_PROGRESSIVE(
        (Prefixed ? kDomainPrefixBytes : 0) +
            static_cast<uint64_t>(absorbed_columns) * sizeof(uint32_t),
        0xffffffffu);
    result[row].words[0] = h0;
    result[row].words[1] = h1;
    result[row].words[2] = h2;
    result[row].words[3] = h3;
    result[row].words[4] = h4;
    result[row].words[5] = h5;
    result[row].words[6] = h6;
    result[row].words[7] = h7;
}

template <bool Prefixed>
__global__ void contiguous_leaf_kernel(
    uint32_t size,
    uint32_t column_count,
    const uint32_t *columns,
    size_t column_stride_words,
    Hash *result) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    uint32_t initial[8];
    initialize_leaf_for<Prefixed>(initial);
    uint32_t h0 = initial[0];
    uint32_t h1 = initial[1];
    uint32_t h2 = initial[2];
    uint32_t h3 = initial[3];
    uint32_t h4 = initial[4];
    uint32_t h5 = initial[5];
    uint32_t h6 = initial[6];
    uint32_t h7 = initial[7];
    uint32_t p0;
    uint32_t p1;
    uint32_t p2;
    uint32_t p3;
    uint32_t p4;
    uint32_t p5;
    uint32_t p6;
    uint32_t p7;
    uint32_t p8;
    uint32_t p9;
    uint32_t p10;
    uint32_t p11;
    uint32_t p12;
    uint32_t p13;
    uint32_t p14;
    uint32_t p15;

#define STWO_LOAD_COLUMN(target, offset)                                  \
    target = columns[                                                      \
        static_cast<size_t>(column + offset) * column_stride_words + row]

    uint32_t column = 0;
    uint64_t compressed_bytes = (Prefixed ? kDomainPrefixBytes : 0);
    while (column_count - column > 16) {
        STWO_LOAD_COLUMN(p0, 0);
        STWO_LOAD_COLUMN(p1, 1);
        STWO_LOAD_COLUMN(p2, 2);
        STWO_LOAD_COLUMN(p3, 3);
        STWO_LOAD_COLUMN(p4, 4);
        STWO_LOAD_COLUMN(p5, 5);
        STWO_LOAD_COLUMN(p6, 6);
        STWO_LOAD_COLUMN(p7, 7);
        STWO_LOAD_COLUMN(p8, 8);
        STWO_LOAD_COLUMN(p9, 9);
        STWO_LOAD_COLUMN(p10, 10);
        STWO_LOAD_COLUMN(p11, 11);
        STWO_LOAD_COLUMN(p12, 12);
        STWO_LOAD_COLUMN(p13, 13);
        STWO_LOAD_COLUMN(p14, 14);
        STWO_LOAD_COLUMN(p15, 15);
        compressed_bytes += 64;
        STWO_COMPRESS_PROGRESSIVE(compressed_bytes, 0);
        column += 16;
    }

    const uint32_t remaining = column_count - column;
    p0 = columns[static_cast<size_t>(column) * column_stride_words + row];
    p1 = remaining > 1
        ? columns[static_cast<size_t>(column + 1) * column_stride_words + row]
        : 0;
    p2 = remaining > 2
        ? columns[static_cast<size_t>(column + 2) * column_stride_words + row]
        : 0;
    p3 = remaining > 3
        ? columns[static_cast<size_t>(column + 3) * column_stride_words + row]
        : 0;
    p4 = remaining > 4
        ? columns[static_cast<size_t>(column + 4) * column_stride_words + row]
        : 0;
    p5 = remaining > 5
        ? columns[static_cast<size_t>(column + 5) * column_stride_words + row]
        : 0;
    p6 = remaining > 6
        ? columns[static_cast<size_t>(column + 6) * column_stride_words + row]
        : 0;
    p7 = remaining > 7
        ? columns[static_cast<size_t>(column + 7) * column_stride_words + row]
        : 0;
    p8 = remaining > 8
        ? columns[static_cast<size_t>(column + 8) * column_stride_words + row]
        : 0;
    p9 = remaining > 9
        ? columns[static_cast<size_t>(column + 9) * column_stride_words + row]
        : 0;
    p10 = remaining > 10
        ? columns[static_cast<size_t>(column + 10) * column_stride_words + row]
        : 0;
    p11 = remaining > 11
        ? columns[static_cast<size_t>(column + 11) * column_stride_words + row]
        : 0;
    p12 = remaining > 12
        ? columns[static_cast<size_t>(column + 12) * column_stride_words + row]
        : 0;
    p13 = remaining > 13
        ? columns[static_cast<size_t>(column + 13) * column_stride_words + row]
        : 0;
    p14 = remaining > 14
        ? columns[static_cast<size_t>(column + 14) * column_stride_words + row]
        : 0;
    p15 = remaining > 15
        ? columns[static_cast<size_t>(column + 15) * column_stride_words + row]
        : 0;
    STWO_COMPRESS_PROGRESSIVE(
        (Prefixed ? kDomainPrefixBytes : 0) +
            static_cast<uint64_t>(column_count) * sizeof(uint32_t),
        0xffffffffu);

    result[row].words[0] = h0;
    result[row].words[1] = h1;
    result[row].words[2] = h2;
    result[row].words[3] = h3;
    result[row].words[4] = h4;
    result[row].words[5] = h5;
    result[row].words[6] = h6;
    result[row].words[7] = h7;

#undef STWO_LOAD_COLUMN
}

// A bounded launch descriptor replaces the full-domain progressive state
// slab. Descriptors travel as kernel arguments; no upload or scratch is used.
struct MixedSegment {
    const uint32_t *columns;
    size_t stride_words;
    size_t capacity_words;
    uint32_t source_size;
    uint32_t reserved;
};
static constexpr uint32_t kMaxMixedSegments = 96;
struct MixedInputs {
    MixedSegment segments[kMaxMixedSegments];
};
static_assert(sizeof(MixedSegment) == 32);
static_assert(sizeof(MixedInputs) + 32 < 4096);

template <bool Prefixed>
__global__ void mixed_leaf_kernel(uint32_t size, uint32_t count,
                                  MixedInputs inputs, uint32_t absorbed_before, uint32_t seed_size,
                                  const ProgressiveState *seed, ProgressiveState *prefix,
                                  Hash *result) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    ProgressiveState initial{};
    if (seed != nullptr) initial = seed[lifted_column_index(row, __ffs(size / seed_size) - 1)];
    else initialize_leaf_for<Prefixed>(initial.hash);
    STWO_LOAD_PROGRESSIVE(initial);
    uint32_t pending = pending_words(absorbed_before);
    uint64_t compressed_bytes = (Prefixed ? kDomainPrefixBytes : 0) +
        static_cast<uint64_t>(absorbed_before - pending) * 4;
    uint64_t words = absorbed_before;
    for (uint32_t segment = 0; segment < count; ++segment) {
        const MixedSegment input = inputs.segments[segment];
        const uint32_t ratio_log = __ffs(size / input.source_size) - 1;
        const uint32_t source_row = lifted_column_index(row, ratio_log);
        const uint32_t columns = input.capacity_words / input.stride_words;
        for (uint32_t column = 0; column < columns; ++column) {
            if (pending == 16) {
                compressed_bytes += 64;
                STWO_COMPRESS_PROGRESSIVE(compressed_bytes, 0);
                pending = 0;
            }
            const uint32_t word = input.columns[
                static_cast<size_t>(column) * input.stride_words + source_row];
            switch (pending++) {
                case 0: p0 = word; break;
                case 1: p1 = word; break;
                case 2: p2 = word; break;
                case 3: p3 = word; break;
                case 4: p4 = word; break;
                case 5: p5 = word; break;
                case 6: p6 = word; break;
                case 7: p7 = word; break;
                case 8: p8 = word; break;
                case 9: p9 = word; break;
                case 10: p10 = word; break;
                case 11: p11 = word; break;
                case 12: p12 = word; break;
                case 13: p13 = word; break;
                case 14: p14 = word; break;
                default: p15 = word; break;
            }
        }
        words += columns;
    }
    if (prefix != nullptr) {
        ProgressiveState &state = prefix[row];
        STWO_STORE_PROGRESSIVE(state);
        return;
    }
    if (pending < 1) p0 = 0;
    if (pending < 2) p1 = 0;
    if (pending < 3) p2 = 0;
    if (pending < 4) p3 = 0;
    if (pending < 5) p4 = 0;
    if (pending < 6) p5 = 0;
    if (pending < 7) p6 = 0;
    if (pending < 8) p7 = 0;
    if (pending < 9) p8 = 0;
    if (pending < 10) p9 = 0;
    if (pending < 11) p10 = 0;
    if (pending < 12) p11 = 0;
    if (pending < 13) p12 = 0;
    if (pending < 14) p13 = 0;
    if (pending < 15) p14 = 0;
    if (pending < 16) p15 = 0;
    STWO_COMPRESS_PROGRESSIVE((Prefixed ? kDomainPrefixBytes : 0) + words * 4,
                              0xffffffffu);
    result[row] = {{h0,h1,h2,h3,h4,h5,h6,h7}};
}

#undef STWO_STORE_PROGRESSIVE
#undef STWO_COMPRESS_PROGRESSIVE
#undef STWO_LOAD_PROGRESSIVE

}  // namespace stwo::cuda::blake2s

template <bool Prefixed>
static int stwo_blake2s_progressive_init_on_impl(
    uint32_t size,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    stwo::cuda::blake2s::DeviceRange state_range{};
    if (stream == nullptr ||
        !stwo::cuda::blake2s::element_range(states, size, &state_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::progressive_init_kernel<Prefixed><<<
        stwo::cuda::blake2s::blocks_for(size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(size, states);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_init_on(
    uint32_t size,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_init_on_impl<true>(size, states, stream);
}

extern "C" int stwo_blake2s_progressive_init_plain_on(
    uint32_t size,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_init_on_impl<false>(size, states, stream);
}

template <bool Prefixed>
static int stwo_blake2s_progressive_absorb_on_impl(
    uint32_t size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange column_range{};
    DeviceRange state_range{};
    uint32_t column_count = 0;
    if (stream == nullptr ||
        !exact_word_slab_range(
            columns,
            column_capacity_words,
            column_stride_words,
            size,
            &column_count,
            &column_range) ||
        !element_range(states, size, &state_range) ||
        absorbed_before > UINT32_MAX - column_count ||
        ranges_overlap(column_range, state_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    progressive_absorb_kernel<Prefixed><<<
        blocks_for(size),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            column_count,
            absorbed_before,
            columns,
            column_stride_words,
            states);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_absorb_on(
    uint32_t size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_absorb_on_impl<true>(size, absorbed_before, columns, column_stride_words, column_capacity_words, states, stream);
}

extern "C" int stwo_blake2s_progressive_absorb_plain_on(
    uint32_t size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_absorb_on_impl<false>(size, absorbed_before, columns, column_stride_words, column_capacity_words, states, stream);
}

template <bool Prefixed>
static int stwo_blake2s_progressive_absorb_lifted_on_impl(
    uint32_t size,
    uint32_t source_size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange column_range{};
    DeviceRange state_range{};
    uint32_t column_count = 0;
    if (stream == nullptr ||
        source_size < 2 ||
        (source_size & (source_size - 1u)) != 0 ||
        (size & (size - 1u)) != 0 ||
        source_size > size ||
        !exact_word_slab_range(
            columns,
            column_capacity_words,
            column_stride_words,
            source_size,
            &column_count,
            &column_range) ||
        !element_range(states, size, &state_range) ||
        absorbed_before > UINT32_MAX - column_count ||
        ranges_overlap(column_range, state_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    uint32_t log_ratio = 0;
    for (uint32_t ratio = size / source_size; ratio > 1; ratio >>= 1) {
        ++log_ratio;
    }
    progressive_absorb_lifted_kernel<Prefixed><<<
        blocks_for(size),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            column_count,
            absorbed_before,
            log_ratio,
            columns,
            column_stride_words,
            states);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_absorb_lifted_on(
    uint32_t size,
    uint32_t source_size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_absorb_lifted_on_impl<true>(size, source_size, absorbed_before, columns, column_stride_words, column_capacity_words, states, stream);
}

extern "C" int stwo_blake2s_progressive_absorb_lifted_plain_on(
    uint32_t size,
    uint32_t source_size,
    uint32_t absorbed_before,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    return stwo_blake2s_progressive_absorb_lifted_on_impl<false>(size, source_size, absorbed_before, columns, column_stride_words, column_capacity_words, states, stream);
}

template <bool Prefixed>
static int stwo_blake2s_progressive_finalize_on_impl(
    uint32_t size,
    uint32_t absorbed_columns,
    const stwo::cuda::blake2s::ProgressiveState *states,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange state_range{};
    DeviceRange result_range{};
    if (stream == nullptr ||
        !element_range(states, size, &state_range) ||
        !element_range(result, size, &result_range) ||
        ranges_overlap(state_range, result_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    progressive_finalize_kernel<Prefixed><<<
        blocks_for(size),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            absorbed_columns,
            states,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_finalize_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const stwo::cuda::blake2s::ProgressiveState *states,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_progressive_finalize_on_impl<true>(size, absorbed_columns, states, result, stream);
}

extern "C" int stwo_blake2s_progressive_finalize_plain_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const stwo::cuda::blake2s::ProgressiveState *states,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_progressive_finalize_on_impl<false>(size, absorbed_columns, states, result, stream);
}

template <bool Prefixed>
static int stwo_blake2s_contiguous_leaf_on_impl(
    uint32_t size,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange column_range{};
    DeviceRange result_range{};
    uint32_t column_count = 0;
    if (stream == nullptr ||
        !exact_word_slab_range(
            columns,
            column_capacity_words,
            column_stride_words,
            size,
            &column_count,
            &column_range) ||
        !element_range(result, size, &result_range) ||
        ranges_overlap(column_range, result_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    contiguous_leaf_kernel<Prefixed><<<
        blocks_for(size),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            column_count,
            columns,
            column_stride_words,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_contiguous_leaf_on(
    uint32_t size,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_contiguous_leaf_on_impl<true>(size, columns, column_stride_words, column_capacity_words, result, stream);
}

extern "C" int stwo_blake2s_contiguous_leaf_plain_on(
    uint32_t size,
    const uint32_t *columns,
    size_t column_stride_words,
    size_t column_capacity_words,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_contiguous_leaf_on_impl<false>(size, columns, column_stride_words, column_capacity_words, result, stream);
}

template <bool Prefixed>
static int mixed_seeded_on(uint32_t size, uint32_t count,
                         const stwo::cuda::blake2s::MixedSegment *segments,
                         uint32_t absorbed_before, uint32_t seed_size,
                         const stwo::cuda::blake2s::ProgressiveState *seed,
                         stwo::cuda::blake2s::ProgressiveState *prefix,
                         stwo::cuda::blake2s::Hash *result, void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange outputs{};
    if (stream == nullptr || segments == nullptr || size < 2 ||
        (size & (size - 1)) != 0 || count == 0 || count > kMaxMixedSegments ||
        ((prefix == nullptr) == (result == nullptr)) ||
        !(prefix != nullptr ? element_range(prefix, size, &outputs) :
                              element_range(result, size, &outputs)))
        return static_cast<int>(cudaErrorInvalidValue);
    DeviceRange previous{};
    if (seed == nullptr) {
        if (absorbed_before != 0 || seed_size != 0)
            return static_cast<int>(cudaErrorInvalidValue);
    } else if (absorbed_before == 0 || seed_size < 2 || seed_size > size ||
               (seed_size & (seed_size - 1)) != 0 ||
               !element_range(seed, seed_size, &previous) ||
               ranges_overlap(previous, outputs)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MixedInputs inputs{};
    uint64_t words = absorbed_before;
    for (uint32_t i = 0; i < count; ++i) {
        const MixedSegment input = segments[i];
        DeviceRange source{};
        uint32_t columns = 0;
        if (input.reserved != 0 || input.source_size < 2 ||
            input.source_size > size ||
            (input.source_size & (input.source_size - 1)) != 0 ||
            !exact_word_slab_range(input.columns, input.capacity_words,
                                   input.stride_words, input.source_size,
                                   &columns, &source) ||
            ranges_overlap(source, outputs))
            return static_cast<int>(cudaErrorInvalidValue);
        words += columns;
        if (words > UINT32_MAX) return static_cast<int>(cudaErrorInvalidValue);
        inputs.segments[i] = input;
    }
    mixed_leaf_kernel<Prefixed><<<blocks_for(size), kBlockSize, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(size, count, inputs, absorbed_before, seed_size, seed, prefix, result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_mixed_leaf_on(uint32_t size, uint32_t count,
    const stwo::cuda::blake2s::MixedSegment *segments,
    stwo::cuda::blake2s::Hash *result, void *stream) {
    return mixed_seeded_on<true>(size, count, segments, 0, 0, nullptr, nullptr, result, stream);
}
extern "C" int stwo_blake2s_mixed_leaf_plain_on(uint32_t size, uint32_t count,
    const stwo::cuda::blake2s::MixedSegment *segments,
    stwo::cuda::blake2s::Hash *result, void *stream) {
    return mixed_seeded_on<false>(size, count, segments, 0, 0, nullptr, nullptr, result, stream);
}

extern "C" int stwo_blake2s_mixed_seeded_on(uint32_t size, uint32_t count,
    const stwo::cuda::blake2s::MixedSegment *segments,
    uint32_t absorbed_before, uint32_t seed_size,
    const stwo::cuda::blake2s::ProgressiveState *seed,
    stwo::cuda::blake2s::ProgressiveState *prefix,
    stwo::cuda::blake2s::Hash *result, void *stream) {
    return mixed_seeded_on<true>(size, count, segments, absorbed_before,
                                 seed_size, seed, prefix, result, stream);
}
extern "C" int stwo_blake2s_mixed_seeded_plain_on(uint32_t size, uint32_t count,
    const stwo::cuda::blake2s::MixedSegment *segments,
    uint32_t absorbed_before, uint32_t seed_size,
    const stwo::cuda::blake2s::ProgressiveState *seed,
    stwo::cuda::blake2s::ProgressiveState *prefix,
    stwo::cuda::blake2s::Hash *result, void *stream) {
    return mixed_seeded_on<false>(size, count, segments, absorbed_before,
                                  seed_size, seed, prefix, result, stream);
}
