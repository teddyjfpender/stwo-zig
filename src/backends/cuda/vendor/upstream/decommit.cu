#include "decommit.cuh"
#include "blake2s.cuh"

#include <cuda_runtime.h>

namespace {

constexpr uint32_t BLOCK = 256;
constexpr uint32_t HASH_WORDS = 8;
constexpr uint32_t AUX_NODE_WORDS = 10; // level, index, hash[8]
constexpr uint32_t M31_P = 0x7fffffffu;

enum HeaderWord : uint32_t {
    H_MAGIC = 0,
    H_VERSION = 1,
    H_TREE_COUNT = 2,
    H_RAW_COUNT = 3,
    H_UNIQUE_COUNT = 4,
    H_RAW_OFFSET = 5,
    H_UNIQUE_OFFSET = 6,
    H_USED_WORDS = 7,
};

enum TreeMetaWord : uint32_t {
    M_KIND = 0,
    M_ROLE = 1,
    M_QUERY_OFFSET = 2,
    M_QUERY_COUNT = 3,
    M_VALUES_OFFSET = 4,
    M_VALUES_COUNT = 5,
    M_FRI_WITNESS_OFFSET = 6,
    M_FRI_WITNESS_COUNT = 7,
    M_HASH_WITNESS_OFFSET = 8,
    M_HASH_WITNESS_COUNT = 9,
    M_AUX_OFFSET = 10,
    M_AUX_COUNT = 11,
    M_ALL_VALUES_OFFSET = 12,
    M_ALL_VALUES_COUNT = 13,
    M_LEAF_LOG_SIZE = 14,
    M_USED_WORDS = 15,
};

__device__ __forceinline__ uint32_t lifted_index(
    uint32_t position,
    uint32_t lifting_log_size,
    uint32_t column_log_size) {
    const uint32_t shift = lifting_log_size - column_log_size;
    return shift == 0
        ? position
        : ((position >> (shift + 1)) << 1) + (position & 1u);
}

__device__ __forceinline__ uint32_t canonical_m31(uint32_t value) {
    // Resident columns may retain the valid unreduced zero representation P.
    // Proof values use Column::at semantics; sparse leaf hashing intentionally
    // continues reading the untouched raw word stream.
    return value < M31_P ? value : value % M31_P;
}

__device__ uint32_t sort_unique(uint32_t *values, uint32_t count) {
    // Query counts are protocol constants (currently O(10^2)); serial insertion
    // sort avoids CUB temporary storage and remains graph-address-stable.
    for (uint32_t i = 1; i < count; ++i) {
        const uint32_t value = values[i];
        uint32_t j = i;
        while (j != 0 && values[j - 1] > value) {
            values[j] = values[j - 1];
            --j;
        }
        values[j] = value;
    }
    uint32_t unique = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (unique == 0 || values[i] != values[unique - 1]) {
            values[unique++] = values[i];
        }
    }
    return unique;
}

__device__ __forceinline__ uint32_t map_query_log(
    uint32_t position,
    uint32_t source_log_size,
    uint32_t target_log_size) {
    if (source_log_size < target_log_size) {
        return ((position >> 1) << (target_log_size - source_log_size + 1)) |
               (position & 1u);
    }
    return ((position >> (source_log_size - target_log_size + 1)) << 1) |
           (position & 1u);
}

__device__ __forceinline__ uint32_t *tree_meta(uint32_t *assembly, uint32_t tree_index) {
    return assembly + STWO_DECOMMIT_HEADER_WORDS +
           tree_index * STWO_DECOMMIT_TREE_META_WORDS;
}

__device__ bool reserve_words(
    uint32_t *assembly,
    uint32_t capacity,
    uint32_t words,
    uint32_t *offset) {
    const uint32_t cursor = assembly[H_USED_WORDS];
    if (cursor > capacity || words > capacity - cursor) {
        assembly[H_USED_WORDS] = 0;
        return false;
    }
    *offset = cursor;
    assembly[H_USED_WORDS] = cursor + words;
    return true;
}

__device__ const Blake2sHash *find_sparse(
    uint32_t level,
    uint32_t index,
    uint32_t leaf_log_size,
    const uint32_t *indices,
    const Blake2sHash *hashes,
    const uint32_t *level_offsets,
    const uint32_t *level_counts,
    uint32_t level_count) {
    const uint32_t distance = leaf_log_size - level;
    if (distance >= level_count) return nullptr;
    const uint32_t offset = level_offsets[distance];
    uint32_t lo = 0;
    uint32_t hi = level_counts[distance];
    while (lo < hi) {
        const uint32_t mid = lo + ((hi - lo) >> 1);
        const uint32_t current = indices[offset + mid];
        if (current < index) lo = mid + 1;
        else hi = mid;
    }
    return (lo < level_counts[distance] && indices[offset + lo] == index)
        ? &hashes[offset + lo]
        : nullptr;
}

__device__ const Blake2sHash *node_hash(
    uint32_t level,
    uint32_t index,
    uint32_t leaf_log_size,
    uint32_t first_retained_log_size,
    const Blake2sHash *const *retained,
    const uint32_t *sparse_indices,
    const Blake2sHash *sparse_hashes,
    const uint32_t *sparse_offsets,
    const uint32_t *sparse_counts,
    uint32_t sparse_level_count) {
    if (level <= first_retained_log_size) {
        return &retained[level][index];
    }
    return find_sparse(level, index, leaf_log_size, sparse_indices, sparse_hashes,
                       sparse_offsets, sparse_counts, sparse_level_count);
}

__device__ void write_hash(uint32_t *destination, const Blake2sHash &hash) {
    #pragma unroll
    for (uint32_t i = 0; i < HASH_WORDS; ++i) destination[i] = hash.s[i];
}

struct TraceNodeSource {
    uint32_t leaf_log_size;
    uint32_t first_retained_log_size;
    const Blake2sHash *const *retained;
    const uint32_t *sparse_indices;
    const Blake2sHash *sparse_hashes;
    const uint32_t *sparse_offsets;
    const uint32_t *sparse_counts;
    uint32_t sparse_level_count;

    __device__ const Blake2sHash *get(uint32_t level, uint32_t index) const {
        return node_hash(level, index, leaf_log_size, first_retained_log_size,
                         retained, sparse_indices, sparse_hashes, sparse_offsets,
                         sparse_counts, sparse_level_count);
    }
};

struct RetainedNodeSource {
    const Blake2sHash *const *retained;

    __device__ const Blake2sHash *get(uint32_t level, uint32_t index) const {
        return &retained[level][index];
    }
};

struct MerkleWalkShared {
    uint32_t group_scan[BLOCK];
    uint32_t hash_scan[BLOCK];
    uint32_t current_count;
    uint32_t layer_groups;
    uint32_t prior_groups;
    uint32_t hash_count;
    uint32_t failed;
    uint32_t *current;
    uint32_t *next;
};

__device__ void inclusive_scan(uint32_t *values) {
    for (uint32_t offset = 1; offset < BLOCK; offset <<= 1) {
        const uint32_t addend = threadIdx.x >= offset
            ? values[threadIdx.x - offset]
            : 0;
        __syncthreads();
        values[threadIdx.x] += addend;
        __syncthreads();
    }
}

template <typename NodeSource>
__device__ bool parallel_merkle_walk(
    uint32_t leaf_log,
    uint32_t max_initial_count,
    uint32_t *walk,
    uint32_t *scratch,
    const uint32_t *walk_count_ptr,
    NodeSource source,
    uint32_t *assembly,
    uint32_t capacity,
    MerkleWalkShared &state,
    uint32_t *hash_offset_out,
    uint32_t *hash_count_out,
    uint32_t *aux_offset_out,
    uint32_t *aux_count_out) {
    const uint32_t tid = threadIdx.x;
    if (tid == 0) {
        state.current_count = min(*walk_count_ptr, max_initial_count);
        state.layer_groups = 0;
        state.prior_groups = 0;
        state.hash_count = 0;
        state.failed = state.current_count == 0;
        state.current = walk;
        state.next = scratch;

        const unsigned long long max_groups =
            static_cast<unsigned long long>(leaf_log) * state.current_count;
        const unsigned long long reserve =
            max_groups * (HASH_WORDS + 2U * AUX_NODE_WORDS);
        const unsigned long long aux_offset =
            static_cast<unsigned long long>(assembly[H_USED_WORDS]) +
            max_groups * HASH_WORDS;
        uint32_t ignored = 0;
        if (reserve > 0xffffffffULL || aux_offset > 0xffffffffULL ||
            !reserve_words(assembly, capacity, static_cast<uint32_t>(reserve),
                           &ignored)) {
            state.failed = 1;
        }
        *hash_offset_out = ignored;
        *aux_offset_out = static_cast<uint32_t>(aux_offset);
    }
    __syncthreads();
    if (state.failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return false;
    }

    const uint32_t hash_offset = *hash_offset_out;
    const uint32_t aux_staging_offset = *aux_offset_out;
    for (int32_t layer = static_cast<int32_t>(leaf_log) - 1; layer >= 0; --layer) {
        const uint32_t count = state.current_count;
        const uint32_t previous_level = static_cast<uint32_t>(layer) + 1U;
        if (tid == 0) state.layer_groups = 0;
        __syncthreads();

        for (uint32_t base = 0; base < count; base += BLOCK) {
            const uint32_t i = base + tid;
            const bool valid = i < count;
            const uint32_t value = valid ? state.current[i] : 0;
            const bool right_of_pair = valid && i != 0 &&
                state.current[i - 1] == (value ^ 1U);
            const bool group_start = valid && !right_of_pair;
            const bool pair = group_start && i + 1 < count &&
                state.current[i + 1] == (value ^ 1U);
            state.group_scan[tid] = group_start;
            state.hash_scan[tid] = group_start && !pair;
            __syncthreads();
            inclusive_scan(state.group_scan);
            inclusive_scan(state.hash_scan);

            const uint32_t group_base = state.layer_groups;
            const uint32_t hash_base = state.hash_count;
            if (group_start) {
                const uint32_t group = group_base + state.group_scan[tid] - 1U;
                const uint32_t parent = value >> 1U;
                state.next[group] = parent;

                if (!pair) {
                    const Blake2sHash *hash = source.get(previous_level, value ^ 1U);
                    if (hash == nullptr) {
                        atomicExch(&state.failed, 1U);
                    } else {
                        const uint32_t hash_index =
                            hash_base + state.hash_scan[tid] - 1U;
                        write_hash(assembly + hash_offset + hash_index * HASH_WORDS,
                                   *hash);
                    }
                }
                for (uint32_t child = 2U * parent; child <= 2U * parent + 1U;
                     ++child) {
                    const Blake2sHash *hash = source.get(previous_level, child);
                    if (hash == nullptr) {
                        atomicExch(&state.failed, 1U);
                    } else {
                        const uint32_t aux_index =
                            2U * (state.prior_groups + group) + (child & 1U);
                        uint32_t *entry = assembly + aux_staging_offset +
                            aux_index * AUX_NODE_WORDS;
                        entry[0] = previous_level;
                        entry[1] = child;
                        write_hash(entry + 2, *hash);
                    }
                }
            }
            __syncthreads();
            if (state.failed) {
                if (tid == 0) assembly[H_USED_WORDS] = 0;
                return false;
            }
            if (tid == 0) {
                const uint32_t valid_count = min(BLOCK, count - base);
                state.layer_groups += state.group_scan[valid_count - 1U];
                state.hash_count += state.hash_scan[valid_count - 1U];
            }
            __syncthreads();
        }

        if (tid == 0) {
            state.prior_groups += state.layer_groups;
            state.current_count = state.layer_groups;
            uint32_t *swap = state.current;
            state.current = state.next;
            state.next = swap;
        }
        __syncthreads();
    }

    if (tid == 0 && state.current_count != 1U) state.failed = 1;
    __syncthreads();
    if (state.failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return false;
    }

    const uint32_t aux_count = 2U * state.prior_groups;
    const uint32_t compact_aux = hash_offset + state.hash_count * HASH_WORDS;
    const uint32_t aux_words = aux_count * AUX_NODE_WORDS;
    // memmove towards lower addresses in shared-memory tiles. The ordered tile
    // loop prevents one block from overwriting a later tile before it is read.
    for (uint32_t base = 0; base < aux_words; base += BLOCK) {
        const uint32_t i = base + tid;
        if (i < aux_words) state.group_scan[tid] = assembly[aux_staging_offset + i];
        __syncthreads();
        if (i < aux_words) assembly[compact_aux + i] = state.group_scan[tid];
        __syncthreads();
    }
    if (tid == 0) {
        assembly[H_USED_WORDS] = compact_aux + aux_words;
        *hash_count_out = state.hash_count;
        *aux_offset_out = compact_aux;
        *aux_count_out = aux_count;
    }
    __syncthreads();
    return true;
}

__global__ void normalize_queries_kernel(
    const uint32_t *raw,
    uint32_t raw_count,
    uint32_t query_log_size,
    uint32_t tree_count,
    uint32_t *unique,
    uint32_t *unique_count,
    uint32_t *assembly,
    uint32_t capacity) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t mask = (1u << query_log_size) - 1u;
    for (uint32_t i = 0; i < raw_count; ++i) unique[i] = raw[i] & mask;
    const uint32_t count = sort_unique(unique, raw_count);
    *unique_count = count;

    const uint32_t raw_offset = STWO_DECOMMIT_HEADER_WORDS +
        tree_count * STWO_DECOMMIT_TREE_META_WORDS;
    const uint32_t unique_offset = raw_offset + raw_count;
    const uint32_t used = unique_offset + count;
    if (used > capacity) {
        assembly[H_USED_WORDS] = 0;
        return;
    }
    assembly[H_MAGIC] = STWO_DECOMMIT_MAGIC;
    assembly[H_VERSION] = STWO_DECOMMIT_VERSION;
    assembly[H_TREE_COUNT] = tree_count;
    assembly[H_RAW_COUNT] = raw_count;
    assembly[H_UNIQUE_COUNT] = count;
    assembly[H_RAW_OFFSET] = raw_offset;
    assembly[H_UNIQUE_OFFSET] = unique_offset;
    assembly[H_USED_WORDS] = used;
    for (uint32_t i = 0; i < tree_count * STWO_DECOMMIT_TREE_META_WORDS; ++i) {
        assembly[STWO_DECOMMIT_HEADER_WORDS + i] = 0;
    }
    for (uint32_t i = 0; i < raw_count; ++i) assembly[raw_offset + i] = raw[i] & mask;
    for (uint32_t i = 0; i < count; ++i) assembly[unique_offset + i] = unique[i];
}

__global__ void prepare_trace_queries_kernel(
    const uint32_t *unique,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t source_log,
    uint32_t tree_log,
    uint32_t leaf_log,
    uint32_t unretained,
    uint32_t *mapped,
    uint32_t *mapped_count,
    uint32_t *walk,
    uint32_t *walk_count,
    uint32_t *leaf_indices,
    uint32_t *leaf_count) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t count = min(*unique_count, max_queries);
    for (uint32_t i = 0; i < count; ++i) {
        mapped[i] = map_query_log(unique[i], source_log, tree_log);
        walk[i] = mapped[i];
    }
    *mapped_count = count;
    const uint32_t dedup = sort_unique(walk, count);
    *walk_count = dedup;

    if (unretained == 0) {
        *leaf_count = 0;
        return;
    }
    const uint32_t span = 1u << unretained;
    uint32_t leaves = 0;
    for (uint32_t i = 0; i < dedup; ++i) {
        const uint32_t base = (walk[i] >> unretained) << unretained;
        for (uint32_t j = 0; j < span; ++j) leaf_indices[leaves++] = base + j;
    }
    *leaf_count = sort_unique(leaf_indices, leaves);
}

__global__ void sparse_parent_kernel(
    const uint32_t *child_indices,
    const Blake2sHash *child_hashes,
    const uint32_t *child_count,
    uint32_t max_child_count,
    uint32_t *parent_indices,
    Blake2sHash *parent_hashes,
    uint32_t *parent_count) {
    const uint32_t parent = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t count = min(*child_count, max_child_count);
    const uint32_t parents = count >> 1;
    if (parent == 0) *parent_count = parents;
    if (parent >= parents) return;
    const uint32_t left = 2 * parent;
    parent_indices[parent] = child_indices[left] >> 1;
    stwo_blake2s_hash2_device(
        reinterpret_cast<const uint8_t *>(&child_hashes[left]), sizeof(Blake2sHash),
        reinterpret_cast<const uint8_t *>(&child_hashes[left + 1]), sizeof(Blake2sHash),
        &parent_hashes[parent]);
}

// Consume one trace source group while its evaluation buffers are live. Recomputed
// groups intentionally reuse one LDE tile, so postponing these reads until final
// assembly would observe a later group. The first group reserves the canonical
// proof-bundle range; every group writes only its disjoint column interval.
__global__ __launch_bounds__(BLOCK)
void pack_trace_group_kernel(
    uint32_t tree_index,
    uint32_t total_column_count,
    uint32_t first_column,
    uint32_t group_column_count,
    const uint32_t *const *columns,
    const uint32_t *column_logs,
    uint32_t lifting_log,
    const uint32_t *mapped,
    const uint32_t *mapped_count_ptr,
    uint32_t max_queries,
    uint32_t *assembly,
    uint32_t capacity) {
    if (blockIdx.x != 0) return;
    const uint32_t tid = threadIdx.x;
    uint32_t *meta = tree_meta(assembly, tree_index);
    __shared__ uint32_t query_offset;
    __shared__ uint32_t value_offset;
    __shared__ uint32_t mapped_count;
    __shared__ uint32_t failed;
    if (tid == 0) {
        mapped_count = min(*mapped_count_ptr, max_queries);
        failed = assembly[H_USED_WORDS] == 0;
        const unsigned long long value_words =
            static_cast<unsigned long long>(total_column_count) * mapped_count;
        if (value_words > 0xffffffffULL) failed = 1;

        if (!failed && first_column == 0) {
            failed = !reserve_words(assembly, capacity, mapped_count, &query_offset);
            if (!failed && !reserve_words(
                    assembly, capacity, static_cast<uint32_t>(value_words),
                    &value_offset)) {
                failed = 1;
            }
            if (!failed) {
                meta[M_QUERY_OFFSET] = query_offset;
                meta[M_QUERY_COUNT] = mapped_count;
                meta[M_VALUES_OFFSET] = value_offset;
                meta[M_VALUES_COUNT] = static_cast<uint32_t>(value_words);
            }
        } else if (!failed) {
            query_offset = meta[M_QUERY_OFFSET];
            value_offset = meta[M_VALUES_OFFSET];
            const uint32_t used = assembly[H_USED_WORDS];
            const uint32_t expected_values = static_cast<uint32_t>(value_words);
            failed = meta[M_QUERY_COUNT] != mapped_count ||
                meta[M_VALUES_COUNT] != expected_values || used > capacity ||
                query_offset > used || mapped_count > used - query_offset ||
                value_offset > used || expected_values > used - value_offset ||
                value_offset != query_offset + mapped_count;
        }
    }
    __syncthreads();

    for (uint32_t column = tid; column < group_column_count; column += BLOCK) {
        if (column_logs[column] > lifting_log) atomicExch(&failed, 1U);
    }
    __syncthreads();
    if (failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return;
    }

    if (first_column == 0) {
        for (uint32_t query = tid; query < mapped_count; query += BLOCK) {
            assembly[query_offset + query] = mapped[query];
        }
    }
    for (uint32_t column = 0; column < group_column_count; ++column) {
        for (uint32_t query = tid; query < mapped_count; query += BLOCK) {
            const uint32_t row =
                lifted_index(mapped[query], lifting_log, column_logs[column]);
            assembly[value_offset +
                     static_cast<size_t>(first_column + column) * mapped_count + query] =
                canonical_m31(columns[column][row]);
        }
    }
}

__global__ __launch_bounds__(BLOCK)
void assemble_trace_kernel(
    uint32_t tree_index,
    uint32_t role,
    uint32_t leaf_log,
    uint32_t first_retained_log,
    uint32_t column_count,
    const uint32_t *mapped_count_ptr,
    uint32_t max_queries,
    uint32_t *walk,
    uint32_t *scratch,
    const uint32_t *walk_count_ptr,
    const Blake2sHash *const *retained,
    const uint32_t *sparse_indices,
    const Blake2sHash *sparse_hashes,
    const uint32_t *sparse_offsets,
    const uint32_t *sparse_counts,
    uint32_t sparse_level_count,
    uint32_t *assembly,
    uint32_t capacity) {
    if (blockIdx.x != 0) return;
    const uint32_t tid = threadIdx.x;
    uint32_t *meta = tree_meta(assembly, tree_index);
    __shared__ uint32_t tree_start;
    __shared__ uint32_t query_offset;
    __shared__ uint32_t value_offset;
    __shared__ uint32_t mapped_count;
    __shared__ uint32_t failed;
    if (tid == 0) {
        mapped_count = min(*mapped_count_ptr, max_queries);
        const unsigned long long value_words =
            static_cast<unsigned long long>(column_count) * mapped_count;
        const uint32_t used = assembly[H_USED_WORDS];
        query_offset = meta[M_QUERY_OFFSET];
        value_offset = meta[M_VALUES_OFFSET];
        tree_start = query_offset;
        failed = used == 0 || used > capacity || value_words > 0xffffffffULL ||
            meta[M_QUERY_COUNT] != mapped_count ||
            meta[M_VALUES_COUNT] != static_cast<uint32_t>(value_words) ||
            query_offset > used || mapped_count > used - query_offset ||
            value_offset > used || static_cast<uint32_t>(value_words) > used - value_offset ||
            value_offset != query_offset + mapped_count;
    }
    __syncthreads();
    if (failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return;
    }

    const uint32_t value_words = column_count * mapped_count;
    __shared__ MerkleWalkShared walk_state;
    __shared__ uint32_t hash_offset;
    __shared__ uint32_t hash_count;
    __shared__ uint32_t aux_offset;
    __shared__ uint32_t aux_count;
    const TraceNodeSource source{
        leaf_log, first_retained_log, retained, sparse_indices, sparse_hashes,
        sparse_offsets, sparse_counts, sparse_level_count};
    if (!parallel_merkle_walk(
            leaf_log, max_queries, walk, scratch, walk_count_ptr, source,
            assembly, capacity, walk_state, &hash_offset, &hash_count,
            &aux_offset, &aux_count)) {
        return;
    }

    if (tid == 0) {
        meta[M_KIND] = 0;
        meta[M_ROLE] = role;
        meta[M_QUERY_OFFSET] = query_offset;
        meta[M_QUERY_COUNT] = mapped_count;
        meta[M_VALUES_OFFSET] = value_offset;
        meta[M_VALUES_COUNT] = value_words;
        meta[M_FRI_WITNESS_OFFSET] = 0;
        meta[M_FRI_WITNESS_COUNT] = 0;
        meta[M_HASH_WITNESS_OFFSET] = hash_offset;
        meta[M_HASH_WITNESS_COUNT] = hash_count;
        meta[M_AUX_OFFSET] = aux_offset;
        meta[M_AUX_COUNT] = aux_count;
        meta[M_ALL_VALUES_OFFSET] = 0;
        meta[M_ALL_VALUES_COUNT] = 0;
        meta[M_LEAF_LOG_SIZE] = leaf_log;
        meta[M_USED_WORDS] = assembly[H_USED_WORDS] - tree_start;
    }
}

__global__ void prepare_fri_queries_kernel(
    const uint32_t *unique,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t cumulative_fold,
    uint32_t fold_step,
    uint32_t packed_log,
    uint32_t *tree_queries,
    uint32_t *tree_count,
    uint32_t *expanded,
    uint32_t *expanded_count,
    uint32_t *walk,
    uint32_t *walk_count) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t count = min(*unique_count, max_queries);
    for (uint32_t i = 0; i < count; ++i) tree_queries[i] = unique[i] >> cumulative_fold;
    const uint32_t queries = sort_unique(tree_queries, count);
    *tree_count = queries;

    uint32_t out = 0;
    uint32_t previous_coset = 0xffffffffu;
    const uint32_t coset_size = 1u << fold_step;
    for (uint32_t i = 0; i < queries; ++i) {
        const uint32_t coset = tree_queries[i] >> fold_step;
        if (coset == previous_coset) continue;
        previous_coset = coset;
        const uint32_t start = coset << fold_step;
        for (uint32_t j = 0; j < coset_size; ++j) expanded[out++] = start + j;
    }
    *expanded_count = out;
    for (uint32_t i = 0; i < out; ++i) walk[i] = expanded[i] >> packed_log;
    *walk_count = sort_unique(walk, out);
}

__device__ bool contains_sorted(const uint32_t *values, uint32_t count, uint32_t target) {
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        const uint32_t mid = lo + ((hi - lo) >> 1);
        if (values[mid] < target) lo = mid + 1;
        else hi = mid;
    }
    return lo < count && values[lo] == target;
}

__global__ __launch_bounds__(BLOCK)
void assemble_fri_kernel(
    uint32_t tree_index,
    uint32_t leaf_log,
    const uint32_t *tree_queries,
    const uint32_t *tree_count_ptr,
    const uint32_t *expanded,
    const uint32_t *expanded_count_ptr,
    const uint32_t *const *coordinates,
    uint32_t *walk,
    uint32_t *scratch,
    const uint32_t *walk_count_ptr,
    const Blake2sHash *const *retained,
    uint32_t *assembly,
    uint32_t capacity) {
    if (blockIdx.x != 0) return;
    const uint32_t tid = threadIdx.x;
    uint32_t *meta = tree_meta(assembly, tree_index);
    __shared__ MerkleWalkShared walk_state;
    __shared__ uint32_t tree_start;
    __shared__ uint32_t query_offset;
    __shared__ uint32_t witness_offset;
    __shared__ uint32_t witness_count;
    __shared__ uint32_t prefix_base;
    __shared__ uint32_t failed;
    const uint32_t query_count = *tree_count_ptr;
    const uint32_t expanded_count = *expanded_count_ptr;
    if (tid == 0) {
        tree_start = assembly[H_USED_WORDS];
        witness_count = 0;
        failed = !reserve_words(assembly, capacity, query_count, &query_offset);
    }
    __syncthreads();
    if (failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return;
    }
    for (uint32_t i = tid; i < query_count; i += BLOCK) {
        assembly[query_offset + i] = tree_queries[i];
    }

    // Count proof-visible FRI witness values in parallel before reserving their
    // exact compact range.
    for (uint32_t base = 0; base < expanded_count; base += BLOCK) {
        const uint32_t i = base + tid;
        const bool emit = i < expanded_count &&
            !contains_sorted(tree_queries, query_count, expanded[i]);
        if (i < expanded_count) scratch[i] = emit;
        walk_state.group_scan[tid] = emit;
        __syncthreads();
        inclusive_scan(walk_state.group_scan);
        if (tid == 0) {
            const uint32_t valid_count = min(BLOCK, expanded_count - base);
            witness_count += walk_state.group_scan[valid_count - 1U];
        }
        __syncthreads();
    }
    if (tid == 0) {
        const unsigned long long words = 4ULL * witness_count;
        failed = words > 0xffffffffULL ||
            !reserve_words(assembly, capacity, static_cast<uint32_t>(words),
                           &witness_offset);
        prefix_base = 0;
    }
    __syncthreads();
    if (failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return;
    }

    // Prefix/scatter preserves expanded-position order exactly.
    for (uint32_t base = 0; base < expanded_count; base += BLOCK) {
        const uint32_t i = base + tid;
        const bool emit = i < expanded_count && scratch[i] != 0;
        walk_state.group_scan[tid] = emit;
        __syncthreads();
        inclusive_scan(walk_state.group_scan);
        if (emit) {
            const uint32_t destination =
                prefix_base + walk_state.group_scan[tid] - 1U;
            #pragma unroll
            for (uint32_t c = 0; c < 4; ++c) {
                assembly[witness_offset + 4U * destination + c] =
                    canonical_m31(coordinates[c][expanded[i]]);
            }
        }
        __syncthreads();
        if (tid == 0) {
            const uint32_t valid_count = min(BLOCK, expanded_count - base);
            prefix_base += walk_state.group_scan[valid_count - 1U];
        }
        __syncthreads();
    }

    __shared__ uint32_t hash_offset;
    __shared__ uint32_t hash_count;
    __shared__ uint32_t aux_offset;
    __shared__ uint32_t aux_count;
    const RetainedNodeSource source{retained};
    if (!parallel_merkle_walk(
            leaf_log, expanded_count, walk, scratch, walk_count_ptr, source,
            assembly, capacity, walk_state, &hash_offset, &hash_count,
            &aux_offset, &aux_count)) {
        return;
    }

    __shared__ uint32_t all_values_offset;
    if (tid == 0) {
        const unsigned long long words = 5ULL * expanded_count;
        failed = words > 0xffffffffULL ||
            !reserve_words(assembly, capacity, static_cast<uint32_t>(words),
                           &all_values_offset);
    }
    __syncthreads();
    if (failed) {
        if (tid == 0) assembly[H_USED_WORDS] = 0;
        return;
    }
    for (uint32_t i = tid; i < expanded_count; i += BLOCK) {
        assembly[all_values_offset + 5U * i] = expanded[i];
        #pragma unroll
        for (uint32_t c = 0; c < 4; ++c) {
            assembly[all_values_offset + 5U * i + 1U + c] =
                canonical_m31(coordinates[c][expanded[i]]);
        }
    }
    __syncthreads();
    if (tid == 0) {
        meta[M_KIND] = 1;
        meta[M_ROLE] = tree_index;
        meta[M_QUERY_OFFSET] = query_offset;
        meta[M_QUERY_COUNT] = query_count;
        meta[M_VALUES_OFFSET] = 0;
        meta[M_VALUES_COUNT] = 0;
        meta[M_FRI_WITNESS_OFFSET] = witness_offset;
        meta[M_FRI_WITNESS_COUNT] = witness_count;
        meta[M_HASH_WITNESS_OFFSET] = hash_offset;
        meta[M_HASH_WITNESS_COUNT] = hash_count;
        meta[M_AUX_OFFSET] = aux_offset;
        meta[M_AUX_COUNT] = aux_count;
        meta[M_ALL_VALUES_OFFSET] = all_values_offset;
        meta[M_ALL_VALUES_COUNT] = expanded_count;
        meta[M_LEAF_LOG_SIZE] = leaf_log;
        meta[M_USED_WORDS] = assembly[H_USED_WORDS] - tree_start;
    }
}

} // namespace

extern "C" int stwo_decommit_normalize_queries_on(
    const uint32_t *raw, uint32_t raw_count, uint32_t log_size, uint32_t tree_count,
    uint32_t *unique, uint32_t *unique_count, uint32_t *assembly,
    uint32_t capacity, void *stream) {
    if (!raw || raw_count == 0 || log_size == 0 || log_size >= 31 || !unique ||
        !unique_count || !assembly || !stream) return cudaErrorInvalidValue;
    normalize_queries_kernel<<<1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        raw, raw_count, log_size, tree_count, unique, unique_count, assembly, capacity);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_prepare_trace_queries_on(
    const uint32_t *unique, const uint32_t *unique_count, uint32_t max_queries,
    uint32_t source_log, uint32_t tree_log, uint32_t leaf_log, uint32_t unretained,
    uint32_t *mapped, uint32_t *mapped_count, uint32_t *walk, uint32_t *walk_count,
    uint32_t *leaves, uint32_t *leaf_count, void *stream) {
    if (!unique || !unique_count || max_queries == 0 || source_log >= 31 || tree_log >= 31 ||
        leaf_log >= 31 || unretained > leaf_log || !mapped || !mapped_count || !walk ||
        !walk_count || !leaves || !leaf_count || !stream) return cudaErrorInvalidValue;
    prepare_trace_queries_kernel<<<1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        unique, unique_count, max_queries, source_log, tree_log, leaf_log, unretained,
        mapped, mapped_count, walk, walk_count, leaves, leaf_count);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_pack_trace_group_on(
    uint32_t tree_index, uint32_t total_column_count, uint32_t first_column,
    uint32_t group_column_count, const uint32_t *const *columns, const uint32_t *logs,
    uint32_t lifting_log, const uint32_t *mapped, const uint32_t *mapped_count,
    uint32_t max_queries, uint32_t *assembly, uint32_t capacity, void *stream) {
    if (total_column_count == 0 || group_column_count == 0 ||
        first_column > total_column_count ||
        group_column_count > total_column_count - first_column || !columns || !logs ||
        lifting_log >= 31 || !mapped || !mapped_count || max_queries == 0 || !assembly ||
        !stream) {
        return cudaErrorInvalidValue;
    }
    pack_trace_group_kernel<<<1, BLOCK, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index, total_column_count, first_column, group_column_count, columns, logs,
        lifting_log, mapped, mapped_count, max_queries, assembly, capacity);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_sparse_parent_on(
    const uint32_t *child_indices, const Blake2sHash *child_hashes,
    const uint32_t *child_count, uint32_t max_child_count, uint32_t *parent_indices,
    Blake2sHash *parent_hashes, uint32_t *parent_count, void *stream) {
    if (!child_indices || !child_hashes || !child_count || max_child_count < 2 ||
        !parent_indices || !parent_hashes || !parent_count || !stream)
        return cudaErrorInvalidValue;
    const uint32_t max_parents = max_child_count >> 1;
    sparse_parent_kernel<<<(max_parents + BLOCK - 1) / BLOCK, BLOCK, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(child_indices, child_hashes, child_count,
        max_child_count, parent_indices, parent_hashes, parent_count);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_assemble_trace_on(
    uint32_t tree_index, uint32_t role, uint32_t leaf_log, uint32_t first_retained_log,
    uint32_t column_count, const uint32_t *mapped_count, uint32_t max_queries,
    uint32_t *walk, uint32_t *walk_scratch, const uint32_t *walk_count,
    const Blake2sHash *const *retained, const uint32_t *sparse_indices,
    const Blake2sHash *sparse_hashes, const uint32_t *sparse_offsets,
    const uint32_t *sparse_counts, uint32_t sparse_level_count, uint32_t *assembly,
    uint32_t capacity, void *stream) {
    if (leaf_log >= 31 || first_retained_log > leaf_log || column_count == 0 ||
        !mapped_count || max_queries == 0 || !walk || !walk_scratch || !walk_count || !retained ||
        !sparse_indices || !sparse_hashes || !sparse_offsets || !sparse_counts ||
        !assembly || !stream) return cudaErrorInvalidValue;
    assemble_trace_kernel<<<1, BLOCK, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index, role, leaf_log, first_retained_log, column_count, mapped_count,
        max_queries, walk, walk_scratch, walk_count, retained, sparse_indices,
        sparse_hashes, sparse_offsets, sparse_counts, sparse_level_count, assembly,
        capacity);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_prepare_fri_queries_on(
    const uint32_t *unique, const uint32_t *unique_count, uint32_t max_queries,
    uint32_t cumulative_fold, uint32_t fold_step, uint32_t packed_log,
    uint32_t *tree_queries, uint32_t *tree_count, uint32_t *expanded,
    uint32_t *expanded_count, uint32_t *walk, uint32_t *walk_count, void *stream) {
    if (!unique || !unique_count || max_queries == 0 || fold_step >= 31 || packed_log >= 31 ||
        !tree_queries || !tree_count || !expanded || !expanded_count || !walk ||
        !walk_count || !stream) return cudaErrorInvalidValue;
    prepare_fri_queries_kernel<<<1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        unique, unique_count, max_queries, cumulative_fold, fold_step, packed_log,
        tree_queries, tree_count, expanded, expanded_count, walk, walk_count);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_assemble_fri_on(
    uint32_t tree_index, uint32_t leaf_log, const uint32_t *tree_queries,
    const uint32_t *tree_count, const uint32_t *expanded, const uint32_t *expanded_count,
    const uint32_t *const *coordinates, uint32_t *walk, uint32_t *walk_scratch,
    const uint32_t *walk_count, const Blake2sHash *const *retained, uint32_t *assembly,
    uint32_t capacity, void *stream) {
    if (leaf_log >= 31 || !tree_queries || !tree_count || !expanded || !expanded_count ||
        !coordinates || !walk || !walk_scratch || !walk_count || !retained || !assembly ||
        !stream)
        return cudaErrorInvalidValue;
    assemble_fri_kernel<<<1, BLOCK, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index, leaf_log, tree_queries, tree_count, expanded, expanded_count,
        coordinates, walk, walk_scratch, walk_count, retained, assembly, capacity);
    return cudaGetLastError();
}
