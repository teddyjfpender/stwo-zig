// Canonical Cairo multiset compaction for padded producer slabs.
//
// A producer column is physically padded, while only a prefix contains logical
// rows. The v1 authority ABI used one descriptor word for both values. This
// product-owned ABI keeps them separate:
// [stride_rows, real_rows, word_base, words_per_instance, instances, dst].
#include <cuda_runtime.h>
#if defined(STWO_CUMETAL)
#include <cub/cub.h>
#else
#include <cub/cub.cuh>
#endif
#include <cstdint>
#include <cstdio>

#define STWO_COMPACT_V2_DESC_WORDS 6u

__global__ void stwo_compact_v2_gather_kernel(
    const uint32_t *const *producer_subs,
    const uint32_t *edge_descs,
    uint32_t edge_count,
    uint32_t tuple_words,
    uint32_t total_rows,
    uint32_t sort_rows,
    uint32_t *tuples,
    uint32_t *indices
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= sort_rows) {
        return;
    }
    indices[row] = row;
    if (row >= total_rows) {
        for (uint32_t word = 0; word < tuple_words; ++word) {
            tuples[(size_t)row * tuple_words + word] = UINT32_MAX;
        }
        return;
    }

    for (uint32_t edge = 0; edge < edge_count; ++edge) {
        const uint32_t *desc =
            edge_descs + (size_t)edge * STWO_COMPACT_V2_DESC_WORDS;
        uint32_t stride_rows = desc[0];
        uint32_t real_rows = desc[1];
        uint32_t edge_rows = real_rows * desc[4];
        uint32_t destination_offset = desc[5];
        if (row < destination_offset || row >= destination_offset + edge_rows) {
            continue;
        }

        uint32_t local_row = row - destination_offset;
        uint32_t instance = local_row / real_rows;
        uint32_t producer_row = local_row % real_rows;
        for (uint32_t word = 0; word < tuple_words; ++word) {
            size_t source_word =
                (size_t)desc[2] + (size_t)instance * desc[3] + word;
            tuples[(size_t)row * tuple_words + word] =
                producer_subs[edge][source_word * stride_rows + producer_row];
        }
        return;
    }
}

__global__ void stwo_compact_v2_key_kernel(
    const uint32_t *tuples,
    const uint32_t *indices,
    uint32_t tuple_words,
    uint32_t word,
    uint32_t sort_rows,
    uint32_t *keys
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row < sort_rows) {
        keys[row] = tuples[(size_t)indices[row] * tuple_words + word];
    }
}

__device__ __forceinline__ bool stwo_compact_v2_tuple_equal(
    const uint32_t *tuples,
    uint32_t lhs,
    uint32_t rhs,
    uint32_t tuple_words
) {
    for (uint32_t word = 0; word < tuple_words; ++word) {
        if (tuples[(size_t)lhs * tuple_words + word] !=
            tuples[(size_t)rhs * tuple_words + word]) {
            return false;
        }
    }
    return true;
}

__device__ __forceinline__ bool stwo_compact_v2_key_equal(
    const uint32_t *tuples,
    uint32_t lhs,
    uint32_t rhs,
    uint32_t tuple_words,
    uint32_t key_words
) {
    for (uint32_t word = 0; word < key_words; ++word) {
        if (tuples[(size_t)lhs * tuple_words + word] !=
            tuples[(size_t)rhs * tuple_words + word]) {
            return false;
        }
    }
    return true;
}

__global__ void stwo_compact_v2_heads_kernel(
    const uint32_t *tuples,
    const uint32_t *indices,
    uint32_t tuple_words,
    uint32_t key_words,
    uint32_t total_rows,
    uint32_t sort_rows,
    uint32_t *heads
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= sort_rows) {
        return;
    }
    if (row >= total_rows) {
        heads[row] = 0;
        return;
    }
    if (row == 0) {
        heads[row] = 1;
        return;
    }

    uint32_t current = indices[row];
    uint32_t previous = indices[row - 1];
    bool same_tuple =
        stwo_compact_v2_tuple_equal(tuples, current, previous, tuple_words);
    if (!same_tuple &&
        stwo_compact_v2_key_equal(
            tuples, current, previous, tuple_words, key_words)) {
#if !defined(STWO_CUMETAL)
        printf(
            "stwo compact v2 trap: key collision at sorted row %u "
            "(tuple %u vs %u)\n",
            row, current, previous);
#endif
        asm("trap;");
    }
    heads[row] = same_tuple ? 0u : 1u;
}

__global__ void stwo_compact_v2_clear_output_kernel(
    uint32_t *const *consumer_cols,
    uint32_t input_count,
    uint32_t consumer_rows
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    for (uint32_t input = 0; input < input_count; ++input) {
        consumer_cols[input][row] = 0;
    }
}

__global__ void stwo_compact_v2_scatter_kernel(
    const uint32_t *tuples,
    const uint32_t *indices,
    const uint32_t *heads,
    const uint32_t *positions,
    uint32_t tuple_words,
    uint32_t total_rows,
    uint32_t *const *consumer_cols,
    uint32_t multiplicity_slot
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= total_rows) {
        return;
    }
    uint32_t compact_row = positions[row] - 1u;
    if (heads[row] != 0u) {
        uint32_t source = indices[row];
        for (uint32_t word = 0; word < tuple_words; ++word) {
            consumer_cols[word][compact_row] =
                tuples[(size_t)source * tuple_words + word];
        }
    }
    atomicAdd(&consumer_cols[multiplicity_slot][compact_row], 1u);
}

__global__ void stwo_compact_v2_finalize_kernel(
    const uint32_t *positions,
    uint32_t total_rows,
    uint32_t tuple_words,
    uint32_t consumer_rows,
    uint32_t enabler_slot,
    uint32_t iota_slot,
    uint32_t multiplicity_slot,
    uint32_t *unique_count,
    uint32_t *const *consumer_cols
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t unique = positions[total_rows - 1u];
    if (row == 0) {
        *unique_count = unique;
        uint32_t expected =
            unique < 16u ? 16u : 1u << (32u - __clz(unique - 1u));
        if (unique == 0u || unique > consumer_rows ||
            expected != consumer_rows) {
#if !defined(STWO_CUMETAL)
            printf(
                "stwo compact v2 trap: unique=%u consumer_rows=%u "
                "expected_pow2=%u total_rows=%u\n",
                unique, consumer_rows, expected, total_rows);
#endif
            asm("trap;");
        }
    }
    if (row >= consumer_rows) {
        return;
    }
    if (row >= unique) {
        for (uint32_t word = 0; word < tuple_words; ++word) {
            consumer_cols[word][row] = consumer_cols[word][0];
        }
        consumer_cols[multiplicity_slot][row] = 0u;
    }
    if (enabler_slot != UINT32_MAX) {
        consumer_cols[enabler_slot][row] = (uint32_t)(row < unique);
    }
    if (iota_slot != UINT32_MAX) {
        consumer_cols[iota_slot][row] = row;
    }
}

extern "C" int stwo_witness_input_compact_v2_on(
    const uint32_t *const *producer_subs_dev,
    const uint32_t *edge_descs_dev,
    uint32_t edge_count,
    uint32_t tuple_words,
    uint32_t key_words,
    uint32_t total_rows,
    uint32_t sort_rows,
    uint32_t consumer_rows,
    uint32_t input_count,
    uint32_t *const *consumer_cols_dev,
    uint32_t enabler_slot,
    uint32_t iota_slot,
    uint32_t multiplicity_slot,
    uint32_t *tuples_dev,
    uint32_t *keys_a_dev,
    uint32_t *keys_b_dev,
    uint32_t *indices_a_dev,
    uint32_t *indices_b_dev,
    uint32_t *heads_dev,
    uint32_t *positions_dev,
    uint32_t *unique_count_dev,
    void *sort_temp_dev,
    size_t sort_temp_bytes,
    void *scan_temp_dev,
    size_t scan_temp_bytes,
    void *stream
) {
    if (edge_count == 0 || tuple_words == 0 || key_words == 0 ||
        key_words > tuple_words || total_rows == 0 || sort_rows < total_rows ||
        (sort_rows & (sort_rows - 1u)) != 0 || consumer_rows == 0 ||
        multiplicity_slot >= input_count) {
        return (int)cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = (cudaStream_t)stream;
    const uint32_t block = 256;
    uint32_t sort_grid = (sort_rows + block - 1u) / block;
    uint32_t consumer_grid = (consumer_rows + block - 1u) / block;
    stwo_compact_v2_gather_kernel<<<sort_grid, block, 0, cuda_stream>>>(
        producer_subs_dev, edge_descs_dev, edge_count, tuple_words, total_rows,
        sort_rows, tuples_dev, indices_a_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }

    uint32_t *current_indices = indices_a_dev;
    uint32_t *next_indices = indices_b_dev;
    cudaError_t error = cudaSuccess;
    for (uint32_t word = tuple_words; word-- > 0;) {
        stwo_compact_v2_key_kernel<<<sort_grid, block, 0, cuda_stream>>>(
            tuples_dev, current_indices, tuple_words, word, sort_rows,
            keys_a_dev);
        error = cudaGetLastError();
        if (error != cudaSuccess) {
            return (int)error;
        }
#if defined(STWO_CUMETAL)
        // CuMetal's CUB compatibility path operates directly on UMA from the
        // host, so complete the producer stream before host-side sorting.
        error = cudaStreamSynchronize(cuda_stream);
        if (error != cudaSuccess) return (int)error;
#endif
        error = cub::DeviceRadixSort::SortPairs(
            sort_temp_dev, sort_temp_bytes,
            keys_a_dev, keys_b_dev, current_indices, next_indices,
            sort_rows, 0, 32, cuda_stream);
        if (error != cudaSuccess) {
            return (int)error;
        }
        uint32_t *swap = current_indices;
        current_indices = next_indices;
        next_indices = swap;
    }

    stwo_compact_v2_heads_kernel<<<sort_grid, block, 0, cuda_stream>>>(
        tuples_dev, current_indices, tuple_words, key_words, total_rows,
        sort_rows, heads_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
#if defined(STWO_CUMETAL)
    error = cudaStreamSynchronize(cuda_stream);
    if (error != cudaSuccess) return (int)error;
#endif
    error = cub::DeviceScan::InclusiveSum(
        scan_temp_dev, scan_temp_bytes, heads_dev, positions_dev, sort_rows,
        cuda_stream);
    if (error != cudaSuccess) {
        return (int)error;
    }
    stwo_compact_v2_clear_output_kernel<<<
        consumer_grid, block, 0, cuda_stream>>>(
        consumer_cols_dev, input_count, consumer_rows);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    uint32_t total_grid = (total_rows + block - 1u) / block;
    stwo_compact_v2_scatter_kernel<<<total_grid, block, 0, cuda_stream>>>(
        tuples_dev, current_indices, heads_dev, positions_dev, tuple_words,
        total_rows, consumer_cols_dev, multiplicity_slot);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    stwo_compact_v2_finalize_kernel<<<
        consumer_grid, block, 0, cuda_stream>>>(
        positions_dev, total_rows, tuple_words, consumer_rows, enabler_slot,
        iota_slot, multiplicity_slot, unique_count_dev, consumer_cols_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    return (int)cudaSuccess;
}
