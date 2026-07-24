#ifndef STWO_ZIG_CUDA_DECOMMIT_CONTRACT_CUH
#define STWO_ZIG_CUDA_DECOMMIT_CONTRACT_CUH

#include <cuda_runtime.h>

#include "../commitment/blake2s_core.cuh"

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::decommit {

using Hash = blake2s::Hash;

constexpr uint32_t kBlockSize = 256;
constexpr uint32_t kHashWords = 8;
constexpr uint32_t kAuxNodeWords = 10;
constexpr uint32_t kHeaderWords = 8;
constexpr uint32_t kTreeMetaWords = 16;
constexpr uint32_t kMagic = 0x44575453u;
constexpr uint32_t kVersion = 1;
constexpr uint32_t kM31Prime = 0x7fffffffu;
constexpr uint32_t kMaxProtocolQueries = 256;

enum HeaderWord : uint32_t {
    kHeaderMagic = 0,
    kHeaderVersion = 1,
    kHeaderTreeCount = 2,
    kHeaderRawCount = 3,
    kHeaderUniqueCount = 4,
    kHeaderRawOffset = 5,
    kHeaderUniqueOffset = 6,
    kHeaderUsedWords = 7,
};

enum TreeMetaWord : uint32_t {
    kMetaKind = 0,
    kMetaRole = 1,
    kMetaQueryOffset = 2,
    kMetaQueryCount = 3,
    kMetaValuesOffset = 4,
    kMetaValuesCount = 5,
    kMetaFriWitnessOffset = 6,
    kMetaFriWitnessCount = 7,
    kMetaHashWitnessOffset = 8,
    kMetaHashWitnessCount = 9,
    kMetaAuxOffset = 10,
    kMetaAuxCount = 11,
    kMetaAllValuesOffset = 12,
    kMetaAllValuesCount = 13,
    kMetaLeafLogSize = 14,
    kMetaUsedWords = 15,
};

// Retained Merkle layers live in one hash slab. Descriptors are indexed by
// tree level and make both the offset and accessible node count explicit.
struct RetainedLayer {
    uint64_t offset_hashes;
    uint32_t hash_count;
    uint32_t reserved;
};

static_assert(sizeof(RetainedLayer) == 16, "retained layer ABI must be 16 bytes");
static_assert(alignof(RetainedLayer) == 8, "retained layer ABI must be 8-byte aligned");

inline bool checked_bytes(size_t count, size_t item_size, size_t *bytes) {
    if (item_size != 0 && count > SIZE_MAX / item_size) return false;
    *bytes = count * item_size;
    return true;
}

inline bool device_ranges_overlap(
    const void *left,
    size_t left_bytes,
    const void *right,
    size_t right_bytes) {
    if (left_bytes == 0 || right_bytes == 0) return false;
    const uintptr_t left_begin = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_begin = reinterpret_cast<uintptr_t>(right);
    if (left_bytes > UINTPTR_MAX - left_begin ||
        right_bytes > UINTPTR_MAX - right_begin) {
        return true;
    }
    return left_begin < right_begin + right_bytes &&
        right_begin < left_begin + left_bytes;
}

inline bool product_fits_u32(uint64_t left, uint64_t right) {
    return left == 0 || right <= UINT32_MAX / left;
}

inline bool slab_fits(size_t stride, size_t count, size_t capacity) {
    return count == 0 || (stride <= SIZE_MAX / count && stride * count <= capacity);
}

__device__ __forceinline__ uint32_t canonical_m31(uint32_t value) {
    return value < kM31Prime ? value : value % kM31Prime;
}

__device__ __forceinline__ uint32_t lifted_index(
    uint32_t position,
    uint32_t lifting_log_size,
    uint32_t column_log_size) {
    const uint32_t shift = lifting_log_size - column_log_size;
    return shift == 0
        ? position
        : ((position >> (shift + 1)) << 1) + (position & 1u);
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

static __device__ uint32_t sort_unique(uint32_t *values, uint32_t count) {
    // Protocol query counts are small and fixed. This serial sort avoids
    // temporary allocation and preserves graph-address stability.
    for (uint32_t index = 1; index < count; ++index) {
        const uint32_t value = values[index];
        uint32_t insertion = index;
        while (insertion != 0 && values[insertion - 1] > value) {
            values[insertion] = values[insertion - 1];
            --insertion;
        }
        values[insertion] = value;
    }
    uint32_t unique_count = 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (unique_count == 0 || values[index] != values[unique_count - 1]) {
            values[unique_count++] = values[index];
        }
    }
    return unique_count;
}

__device__ __forceinline__ bool valid_assembly(
    const uint32_t *assembly,
    uint32_t capacity_words) {
    if (capacity_words < kHeaderWords) return false;
    const uint32_t used = assembly[kHeaderUsedWords];
    return assembly[kHeaderMagic] == kMagic &&
        assembly[kHeaderVersion] == kVersion &&
        assembly[kHeaderTreeCount] <=
            (capacity_words - kHeaderWords) / kTreeMetaWords &&
        used >= kHeaderWords +
            assembly[kHeaderTreeCount] * kTreeMetaWords &&
        used <= capacity_words;
}

__device__ __forceinline__ uint32_t *checked_tree_meta(
    uint32_t *assembly,
    uint32_t capacity_words,
    uint32_t tree_index) {
    if (!valid_assembly(assembly, capacity_words) ||
        tree_index >= assembly[kHeaderTreeCount]) {
        return nullptr;
    }
    return assembly + kHeaderWords + tree_index * kTreeMetaWords;
}

static __device__ __forceinline__ bool reserve_words(
    uint32_t *assembly,
    uint32_t capacity_words,
    uint32_t word_count,
    uint32_t *offset) {
    if (!valid_assembly(assembly, capacity_words)) return false;
    const uint32_t cursor = assembly[kHeaderUsedWords];
    if (word_count > capacity_words - cursor) {
        assembly[kHeaderUsedWords] = 0;
        return false;
    }
    *offset = cursor;
    assembly[kHeaderUsedWords] = cursor + word_count;
    return true;
}

__device__ __forceinline__ void fail_assembly(uint32_t *assembly) {
    assembly[kHeaderUsedWords] = 0;
}

__device__ __forceinline__ void write_hash(
    uint32_t *destination,
    const Hash &hash) {
#pragma unroll
    for (uint32_t index = 0; index < kHashWords; ++index) {
        destination[index] = hash.words[index];
    }
}

struct RetainedNodeSource {
    const Hash *slab;
    uint64_t slab_hash_count;
    const RetainedLayer *layers;
    uint32_t layer_count;

    __device__ const Hash *get(uint32_t level, uint32_t index) const {
        if (level >= layer_count) return nullptr;
        const RetainedLayer descriptor = layers[level];
        if (descriptor.reserved != 0 || index >= descriptor.hash_count ||
            descriptor.offset_hashes > slab_hash_count ||
            descriptor.hash_count > slab_hash_count - descriptor.offset_hashes) {
            return nullptr;
        }
        return slab + descriptor.offset_hashes + index;
    }
};

struct TraceNodeSource {
    uint32_t leaf_log_size;
    uint32_t first_retained_log_size;
    RetainedNodeSource retained;
    const uint32_t *sparse_indices;
    const Hash *sparse_hashes;
    uint32_t sparse_capacity;
    const uint32_t *sparse_offsets;
    const uint32_t *sparse_counts;
    uint32_t sparse_level_count;

    __device__ const Hash *get(uint32_t level, uint32_t index) const {
        if (level > leaf_log_size) return nullptr;
        if (level <= first_retained_log_size) return retained.get(level, index);
        const uint32_t distance = leaf_log_size - level;
        if (distance >= sparse_level_count) return nullptr;
        const uint32_t offset = sparse_offsets[distance];
        const uint32_t count = sparse_counts[distance];
        if (offset > sparse_capacity || count > sparse_capacity - offset) {
            return nullptr;
        }
        uint32_t lower = 0;
        uint32_t upper = count;
        while (lower < upper) {
            const uint32_t middle = lower + ((upper - lower) >> 1);
            if (sparse_indices[offset + middle] < index) {
                lower = middle + 1;
            } else {
                upper = middle;
            }
        }
        return lower < count && sparse_indices[offset + lower] == index
            ? sparse_hashes + offset + lower
            : nullptr;
    }
};

}  // namespace stwo::cuda::decommit

#endif
