// Device component edges (the device DAG, B3): gather a CONSUMER component's
// input columns directly from a PRODUCER's word-major sub buffer — the
// device-to-device replacement for the host input-list feed (D2H → packed
// rebuild → add_packed_inputs → consumer re-reads).
//
// Layout contract (matches the host feed semantics exactly):
//   producer sub word (word_base + j*words_per_instance + k) at producer row r
//     == consumer input column k at consumer row (j*producer_rows + r)
// because the host feeds instance j's full column before instance j+1
// (`.iter().for_each(add_packed_inputs)` in declaration order) and each feed
// appends producer_rows rows.
//
// Consumer padding: the consumer's writer pads the STACKED input set to the
// next power of two by repeating its FIRST PACKED ROW (16 lanes). The gather
// replicates rows [0, 16) of the stacked set into every padding row group,
// byte-identical to the host `resize(packed_size, first)` on packed inputs.
#include <cuda_runtime.h>
#include <cub/cub.cuh>
#include <cstdint>
#include <cstdio>

#define WIG_DESC_STRIDE 5u

__global__ void witness_edge_gather_kernel(
    const uint32_t *producer_sub,
    uint32_t producer_rows,
    uint32_t word_base,
    uint32_t words_per_instance,
    uint32_t n_instances,
    uint32_t consumer_rows, // padded (power of two, >= n_instances*producer_rows)
    uint32_t *const *consumer_cols // words_per_instance column pointers
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    uint32_t real_rows = n_instances * producer_rows;
    // Padding rows replicate the first PACKED row's lanes (row % 16 of rows 0..16).
    uint32_t src_row = row < real_rows ? row : (row & 15u);
    uint32_t j = src_row / producer_rows;
    uint32_t r = src_row % producer_rows;
    for (uint32_t k = 0; k < words_per_instance; ++k) {
        consumer_cols[k][row] =
            producer_sub[(size_t)(word_base + (size_t)j * words_per_instance + k) *
                             producer_rows +
                         r];
    }
}

// Returns 0 on success. All pointers are DEVICE pointers; `consumer_cols_dev`
// is a device array of `words_per_instance` column pointers, each
// `consumer_rows` long.
extern "C" int stwo_witness_edge_gather(
    const uint32_t *producer_sub_dev,
    uint32_t producer_rows,
    uint32_t word_base,
    uint32_t words_per_instance,
    uint32_t n_instances,
    uint32_t consumer_rows,
    uint32_t *const *consumer_cols_dev
) {
    if (consumer_rows == 0 || words_per_instance == 0) {
        return 0;
    }
    if ((size_t)n_instances * producer_rows > consumer_rows) {
        fprintf(stderr, "stwo_witness_edge_gather: consumer_rows too small\n");
        return 1;
    }
    const uint32_t block = 256;
    uint32_t grid = 1u + (consumer_rows - 1u) / block;
    witness_edge_gather_kernel<<<grid, block>>>(
        producer_sub_dev, producer_rows, word_base, words_per_instance, n_instances,
        consumer_rows, consumer_cols_dev);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_edge_gather: launch failed\n");
        return 1;
    }
    return 0;
}

// Prepared multi-producer form. Descriptor words per canonical edge:
// [producer_rows, word_base, words_per_instance, n_instances, destination_row_offset].
// Source/output pointer arrays and descriptors are DEVICE-resident and stable.
__global__ void witness_input_gather_kernel(
    const uint32_t *const *producer_subs,
    const uint32_t *edge_descs,
    uint32_t n_edges,
    uint32_t input_width,
    uint32_t total_real_rows,
    uint32_t consumer_rows,
    uint32_t *const *consumer_cols,
    uint32_t include_enabler,
    uint32_t include_iota
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    // Host `resize(packed_size, first)` repeats its first packed-16 row.
    uint32_t source_global_row = row < total_real_rows ? row : (row & 15u);
    for (uint32_t edge = 0; edge < n_edges; ++edge) {
        const uint32_t *desc = edge_descs + (size_t)edge * WIG_DESC_STRIDE;
        uint32_t producer_rows = desc[0];
        uint32_t edge_rows = producer_rows * desc[3];
        uint32_t destination_offset = desc[4];
        if (source_global_row < destination_offset ||
            source_global_row >= destination_offset + edge_rows) {
            continue;
        }
        uint32_t local_row = source_global_row - destination_offset;
        uint32_t instance = local_row / producer_rows;
        uint32_t producer_row = local_row % producer_rows;
        for (uint32_t word = 0; word < input_width; ++word) {
            size_t source_word =
                (size_t)desc[1] + (size_t)instance * desc[2] + word;
            consumer_cols[word][row] =
                producer_subs[edge][source_word * producer_rows + producer_row];
        }
        break;
    }
    uint32_t tail = input_width;
    if (include_enabler != 0u) {
        consumer_cols[tail++][row] = (uint32_t)(row < total_real_rows);
    }
    if (include_iota != 0u) {
        consumer_cols[tail][row] = row;
    }
}

extern "C" int stwo_witness_input_gather_on(
    const uint32_t *const *producer_subs_dev,
    const uint32_t *edge_descs_dev,
    uint32_t n_edges,
    uint32_t input_width,
    uint32_t total_real_rows,
    uint32_t consumer_rows,
    uint32_t *const *consumer_cols_dev,
    uint32_t include_enabler,
    uint32_t include_iota,
    void *stream
) {
    if (n_edges == 0 || input_width == 0 || consumer_rows == 0) {
        return 1;
    }
    const uint32_t block = 256;
    uint32_t grid = 1u + (consumer_rows - 1u) / block;
    witness_input_gather_kernel<<<grid, block, 0, (cudaStream_t)stream>>>(
        producer_subs_dev, edge_descs_dev, n_edges, input_width, total_real_rows,
        consumer_rows, consumer_cols_dev, include_enabler, include_iota);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_input_gather_on: launch failed\n");
        return 1;
    }
    return 0;
}

// Prepared compact-metadata form for StoredLogSize builtin writers. Setup
// uploads only `n_scalars` words (for example the builtin segment start); this
// kernel expands those scalars and the mechanical enabler/iota tail directly
// into the stable recorder input columns on the proof stream.
__global__ void witness_input_seed_kernel(
    const uint32_t *scalars,
    uint32_t n_scalars,
    uint32_t n_real_rows,
    uint32_t consumer_rows,
    uint32_t *const *consumer_cols,
    uint32_t include_enabler,
    uint32_t include_iota
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    for (uint32_t scalar = 0; scalar < n_scalars; ++scalar) {
        consumer_cols[scalar][row] = scalars[scalar];
    }
    uint32_t tail = n_scalars;
    if (include_enabler != 0u) {
        consumer_cols[tail++][row] = (uint32_t)(row < n_real_rows);
    }
    if (include_iota != 0u) {
        consumer_cols[tail][row] = row;
    }
}

extern "C" int stwo_witness_input_seed_on(
    const uint32_t *scalars_dev,
    uint32_t n_scalars,
    uint32_t n_real_rows,
    uint32_t consumer_rows,
    uint32_t *const *consumer_cols_dev,
    uint32_t include_enabler,
    uint32_t include_iota,
    void *stream
) {
    if (n_scalars == 0 || n_real_rows == 0 || n_real_rows > consumer_rows ||
        consumer_rows == 0) {
        return 1;
    }
    const uint32_t block = 256;
    uint32_t grid = 1u + (consumer_rows - 1u) / block;
    witness_input_seed_kernel<<<grid, block, 0, (cudaStream_t)stream>>>(
        scalars_dev, n_scalars, n_real_rows, consumer_rows, consumer_cols_dev,
        include_enabler, include_iota);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_input_seed_on: launch failed\n");
        return 1;
    }
    return 0;
}

// Canonical device multiset compaction. Producer sub-inputs are first gathered
// into a row-major tuple slab, then stably radix-sorted from the last tuple word
// to the first. Sorting the complete tuple makes equal tuples contiguous; the
// shorter key prefix is checked separately so a supposedly functionally
// determined suffix can never introduce host-order-dependent proof bytes.

__global__ void witness_input_compact_gather_kernel(
    const uint32_t *const *producer_subs,
    const uint32_t *edge_descs,
    uint32_t n_edges,
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
    for (uint32_t edge = 0; edge < n_edges; ++edge) {
        const uint32_t *desc = edge_descs + (size_t)edge * WIG_DESC_STRIDE;
        uint32_t producer_rows = desc[0];
        uint32_t edge_rows = producer_rows * desc[3];
        uint32_t destination_offset = desc[4];
        if (row < destination_offset || row >= destination_offset + edge_rows) {
            continue;
        }
        uint32_t local_row = row - destination_offset;
        uint32_t instance = local_row / producer_rows;
        uint32_t producer_row = local_row % producer_rows;
        for (uint32_t word = 0; word < tuple_words; ++word) {
            size_t source_word =
                (size_t)desc[1] + (size_t)instance * desc[2] + word;
            tuples[(size_t)row * tuple_words + word] =
                producer_subs[edge][source_word * producer_rows + producer_row];
        }
        return;
    }
}

__global__ void witness_input_compact_key_kernel(
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

__device__ __forceinline__ bool witness_tuple_equal(
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

__device__ __forceinline__ bool witness_key_equal(
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

__global__ void witness_input_compact_heads_kernel(
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
    bool same_tuple = witness_tuple_equal(tuples, current, previous, tuple_words);
    // The host writers sort only by their declared key prefix. A distinct full
    // tuple with the same key would make their order depend on DashMap iteration.
    // Reject that unsupported geometry instead of silently producing different
    // proof bytes.
    if (!same_tuple &&
        witness_key_equal(tuples, current, previous, tuple_words, key_words)) {
        printf(
            "stwo compact trap: key collision at sorted row %u (tuple %u vs %u): "
            "same %u-word key, different %u-word tuple; key0=%u key1=%u\n",
            row, current, previous, key_words, tuple_words,
            tuples[(size_t)current * tuple_words],
            key_words > 1 ? tuples[(size_t)current * tuple_words + 1] : 0u);
        asm("trap;");
    }
    heads[row] = same_tuple ? 0u : 1u;
}

__global__ void witness_input_compact_clear_output_kernel(
    uint32_t *const *consumer_cols,
    uint32_t n_inputs,
    uint32_t consumer_rows
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    for (uint32_t input = 0; input < n_inputs; ++input) {
        consumer_cols[input][row] = 0;
    }
}

__global__ void witness_input_compact_scatter_kernel(
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

__global__ void witness_input_compact_finalize_kernel(
    const uint32_t *positions,
    uint32_t total_rows,
    uint32_t tuple_words,
    uint32_t consumer_rows,
    uint32_t enabler_slot,
    uint32_t iota_slot,
    uint32_t multiplicity_slot,
    uint32_t *n_unique,
    uint32_t *const *consumer_cols
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t unique = positions[total_rows - 1u];
    if (row == 0) {
        *n_unique = unique;
        uint32_t expected = unique < 16u ? 16u : 1u << (32u - __clz(unique - 1u));
        if (unique == 0u || unique > consumer_rows || expected != consumer_rows) {
            printf(
                "stwo compact trap: unique=%u consumer_rows=%u expected_pow2=%u "
                "total_rows=%u\n",
                unique, consumer_rows, expected, total_rows);
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

extern "C" int stwo_witness_input_compact_sort_temp_bytes(
    uint32_t rows,
    size_t *out_bytes
) {
    if (out_bytes == nullptr) {
        return (int)cudaErrorInvalidValue;
    }
    *out_bytes = 0;
    if (rows == 0) {
        return (int)cudaErrorInvalidValue;
    }
    size_t bytes = 0;
    cudaError_t error = cub::DeviceRadixSort::SortPairs(
        nullptr, bytes,
        (const uint32_t *)nullptr, (uint32_t *)nullptr,
        (const uint32_t *)nullptr, (uint32_t *)nullptr,
        rows, 0, 32);
    if (error != cudaSuccess) {
        return (int)error;
    }
    if (bytes == 0) {
        return (int)cudaErrorInvalidValue;
    }
    *out_bytes = bytes;
    return (int)cudaSuccess;
}

extern "C" int stwo_witness_input_compact_scan_temp_bytes(
    uint32_t rows,
    size_t *out_bytes
) {
    if (out_bytes == nullptr) {
        return (int)cudaErrorInvalidValue;
    }
    *out_bytes = 0;
    if (rows == 0) {
        return (int)cudaErrorInvalidValue;
    }
    size_t bytes = 0;
    cudaError_t error = cub::DeviceScan::InclusiveSum(
        nullptr, bytes, (const uint32_t *)nullptr, (uint32_t *)nullptr, rows);
    if (error != cudaSuccess) {
        return (int)error;
    }
    if (bytes == 0) {
        return (int)cudaErrorInvalidValue;
    }
    *out_bytes = bytes;
    return (int)cudaSuccess;
}

extern "C" int stwo_witness_input_compact_on(
    const uint32_t *const *producer_subs_dev,
    const uint32_t *edge_descs_dev,
    uint32_t n_edges,
    uint32_t tuple_words,
    uint32_t key_words,
    uint32_t total_rows,
    uint32_t sort_rows,
    uint32_t consumer_rows,
    uint32_t n_inputs,
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
    uint32_t *n_unique_dev,
    void *sort_temp_dev,
    size_t sort_temp_bytes,
    void *scan_temp_dev,
    size_t scan_temp_bytes,
    void *stream
) {
    if (n_edges == 0 || tuple_words == 0 || key_words == 0 ||
        key_words > tuple_words || total_rows == 0 || sort_rows < total_rows ||
        (sort_rows & (sort_rows - 1u)) != 0 || consumer_rows == 0 ||
        multiplicity_slot >= n_inputs) {
        return 1;
    }
    cudaStream_t cuda_stream = (cudaStream_t)stream;
    const uint32_t block = 256;
    uint32_t sort_grid = (sort_rows + block - 1u) / block;
    uint32_t consumer_grid = 1u + (consumer_rows - 1u) / block;
    witness_input_compact_gather_kernel<<<sort_grid, block, 0, cuda_stream>>>(
        producer_subs_dev, edge_descs_dev, n_edges, tuple_words, total_rows,
        sort_rows, tuples_dev, indices_a_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }

    uint32_t *current_indices = indices_a_dev;
    uint32_t *next_indices = indices_b_dev;
    for (uint32_t word = tuple_words; word-- > 0;) {
        witness_input_compact_key_kernel<<<sort_grid, block, 0, cuda_stream>>>(
            tuples_dev, current_indices, tuple_words, word, sort_rows, keys_a_dev);
        cudaError_t error = cudaGetLastError();
        if (error != cudaSuccess) {
            return 1;
        }
        error = cub::DeviceRadixSort::SortPairs(
            sort_temp_dev, sort_temp_bytes,
            keys_a_dev, keys_b_dev, current_indices, next_indices,
            sort_rows, 0, 32, cuda_stream);
        if (error != cudaSuccess) {
            return 1;
        }
        uint32_t *swap = current_indices;
        current_indices = next_indices;
        next_indices = swap;
    }

    witness_input_compact_heads_kernel<<<sort_grid, block, 0, cuda_stream>>>(
        tuples_dev, current_indices, tuple_words, key_words, total_rows,
        sort_rows, heads_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    cudaError_t error = cub::DeviceScan::InclusiveSum(
        scan_temp_dev, scan_temp_bytes, heads_dev, positions_dev, sort_rows,
        cuda_stream);
    if (error != cudaSuccess) {
        return 1;
    }
    witness_input_compact_clear_output_kernel<<<consumer_grid, block, 0, cuda_stream>>>(
        consumer_cols_dev, n_inputs, consumer_rows);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    uint32_t total_grid = (total_rows + block - 1u) / block;
    witness_input_compact_scatter_kernel<<<total_grid, block, 0, cuda_stream>>>(
        tuples_dev, current_indices, heads_dev, positions_dev, tuple_words,
        total_rows, consumer_cols_dev, multiplicity_slot);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    witness_input_compact_finalize_kernel<<<consumer_grid, block, 0, cuda_stream>>>(
        positions_dev, total_rows, tuple_words, consumer_rows, enabler_slot,
        iota_slot, multiplicity_slot, n_unique_dev, consumer_cols_dev);
    if (cudaGetLastError() != cudaSuccess) {
        return 1;
    }
    return 0;
}
