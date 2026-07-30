#ifndef STWO_ZIG_CUDA_DECOMMIT_MERKLE_WALK_CUH
#define STWO_ZIG_CUDA_DECOMMIT_MERKLE_WALK_CUH

#include "contract.cuh"

namespace stwo::cuda::decommit {

struct MerkleWalkShared {
    uint32_t group_scan[kBlockSize];
    uint32_t hash_scan[kBlockSize];
    uint32_t current_count;
    uint32_t layer_groups;
    uint32_t prior_groups;
    uint32_t hash_count;
    uint32_t failed;
    uint32_t *current;
    uint32_t *next;
};

static __device__ __forceinline__ void inclusive_scan(uint32_t *values) {
    for (uint32_t offset = 1; offset < kBlockSize; offset <<= 1) {
        const uint32_t addend =
            threadIdx.x >= offset ? values[threadIdx.x - offset] : 0;
        __syncthreads();
        values[threadIdx.x] += addend;
        __syncthreads();
    }
}

template <typename NodeSource>
__device__ bool merkle_walk(
    uint32_t leaf_log_size,
    uint32_t walk_capacity,
    uint32_t *walk,
    uint32_t *scratch,
    const uint32_t *walk_count_pointer,
    NodeSource source,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    MerkleWalkShared &state,
    uint32_t *hash_offset_output,
    uint32_t *hash_count_output,
    uint32_t *aux_offset_output,
    uint32_t *aux_count_output) {
    const uint32_t lane = threadIdx.x;
    if (lane == 0) {
        state.current_count = *walk_count_pointer;
        state.layer_groups = 0;
        state.prior_groups = 0;
        state.hash_count = 0;
        state.failed =
            state.current_count == 0 || state.current_count > walk_capacity;
        state.current = walk;
        state.next = scratch;

        const uint32_t level_capacity =
            leaf_log_size == 0 ? 1u : (1u << leaf_log_size);
        for (uint32_t index = 0;
             !state.failed && index < state.current_count;
             ++index) {
            state.failed = state.current[index] >= level_capacity ||
                (index != 0 && state.current[index - 1] >= state.current[index]);
        }

        const uint64_t max_groups =
            static_cast<uint64_t>(leaf_log_size) * state.current_count;
        const uint64_t hash_staging_words = max_groups * kHashWords;
        const uint64_t reserve =
            hash_staging_words + 2u * max_groups * kAuxNodeWords;
        const uint64_t aux_staging =
            static_cast<uint64_t>(assembly[kHeaderUsedWords]) +
            hash_staging_words;
        uint32_t hash_offset = 0;
        if (state.failed || reserve > UINT32_MAX ||
            aux_staging > UINT32_MAX ||
            !reserve_words(
                assembly,
                assembly_capacity_words,
                static_cast<uint32_t>(reserve),
                &hash_offset)) {
            state.failed = 1;
        }
        *hash_offset_output = hash_offset;
        *aux_offset_output = static_cast<uint32_t>(aux_staging);
    }
    __syncthreads();
    if (state.failed) {
        if (lane == 0) fail_assembly(assembly);
        return false;
    }

    const uint32_t hash_offset = *hash_offset_output;
    const uint32_t aux_staging_offset = *aux_offset_output;
    for (int32_t layer = static_cast<int32_t>(leaf_log_size) - 1;
         layer >= 0;
         --layer) {
        const uint32_t count = state.current_count;
        const uint32_t child_level = static_cast<uint32_t>(layer) + 1u;
        if (lane == 0) state.layer_groups = 0;
        __syncthreads();

        for (uint32_t base = 0; base < count; base += kBlockSize) {
            const uint32_t index = base + lane;
            const bool valid = index < count;
            const uint32_t value = valid ? state.current[index] : 0;
            const bool right_of_pair = valid && index != 0 &&
                state.current[index - 1] == (value ^ 1u);
            const bool group_start = valid && !right_of_pair;
            const bool pair = group_start && index + 1 < count &&
                state.current[index + 1] == (value ^ 1u);
            state.group_scan[lane] = group_start;
            state.hash_scan[lane] = group_start && !pair;
            __syncthreads();
            inclusive_scan(state.group_scan);
            inclusive_scan(state.hash_scan);

            const uint32_t group_base = state.layer_groups;
            const uint32_t hash_base = state.hash_count;
            if (group_start) {
                const uint32_t group =
                    group_base + state.group_scan[lane] - 1u;
                const uint32_t parent = value >> 1u;
                state.next[group] = parent;

                if (!pair) {
                    const Hash *sibling = source.get(child_level, value ^ 1u);
                    if (sibling == nullptr) {
                        atomicExch(&state.failed, 1u);
                    } else {
                        const uint32_t hash_index =
                            hash_base + state.hash_scan[lane] - 1u;
                        write_hash(
                            assembly + hash_offset +
                                hash_index * kHashWords,
                            *sibling);
                    }
                }
                for (uint32_t child = 2u * parent;
                     child <= 2u * parent + 1u;
                     ++child) {
                    const Hash *child_hash = source.get(child_level, child);
                    if (child_hash == nullptr) {
                        atomicExch(&state.failed, 1u);
                    } else {
                        const uint32_t aux_index =
                            2u * (state.prior_groups + group) + (child & 1u);
                        uint32_t *entry = assembly + aux_staging_offset +
                            aux_index * kAuxNodeWords;
                        entry[0] = child_level;
                        entry[1] = child;
                        write_hash(entry + 2, *child_hash);
                    }
                }
            }
            __syncthreads();
            if (state.failed) {
                if (lane == 0) fail_assembly(assembly);
                return false;
            }
            if (lane == 0) {
                const uint32_t active =
                    min(kBlockSize, count - base);
                state.layer_groups += state.group_scan[active - 1u];
                state.hash_count += state.hash_scan[active - 1u];
            }
            __syncthreads();
        }

        if (lane == 0) {
            state.prior_groups += state.layer_groups;
            state.current_count = state.layer_groups;
            uint32_t *old_current = state.current;
            state.current = state.next;
            state.next = old_current;
        }
        __syncthreads();
    }

    if (lane == 0 && state.current_count != 1u) state.failed = 1;
    __syncthreads();
    if (state.failed) {
        if (lane == 0) fail_assembly(assembly);
        return false;
    }

    const uint32_t aux_count = 2u * state.prior_groups;
    const uint32_t compact_aux =
        hash_offset + state.hash_count * kHashWords;
    const uint32_t aux_words = aux_count * kAuxNodeWords;
    // The destination precedes the staging range. Tiled reads complete before
    // writes, preserving memmove semantics without a second global buffer.
    for (uint32_t base = 0; base < aux_words; base += kBlockSize) {
        const uint32_t index = base + lane;
        if (index < aux_words) {
            state.group_scan[lane] = assembly[aux_staging_offset + index];
        }
        __syncthreads();
        if (index < aux_words) {
            assembly[compact_aux + index] = state.group_scan[lane];
        }
        __syncthreads();
    }
    if (lane == 0) {
        assembly[kHeaderUsedWords] = compact_aux + aux_words;
        *hash_count_output = state.hash_count;
        *aux_offset_output = compact_aux;
        *aux_count_output = aux_count;
    }
    __syncthreads();
    return true;
}

}  // namespace stwo::cuda::decommit

#endif
