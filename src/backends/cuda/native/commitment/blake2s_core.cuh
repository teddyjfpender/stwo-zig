#ifndef STWO_ZIG_CUDA_BLAKE2S_CORE_CUH
#define STWO_ZIG_CUDA_BLAKE2S_CORE_CUH

#include "blake2s_domain_states.h"

#include <stdint.h>
#include <stddef.h>

namespace stwo::cuda::blake2s {

constexpr uint32_t kBlockSize = 256;
constexpr uint64_t kDomainPrefixBytes = 64;
constexpr uint32_t kLeafTag = 0x6661656cu;
constexpr uint32_t kNodeTag = 0x65646f6eu;

struct alignas(32) Hash {
    uint32_t words[8];
};

struct ProgressiveState {
    uint32_t hash[8];
    uint32_t pending[16];
};

static_assert(sizeof(Hash) == 32, "Blake2s hash ABI must be 32 bytes");
static_assert(alignof(Hash) == 32, "Blake2s hash ABI must be 32-byte aligned");
static_assert(sizeof(ProgressiveState) == 96,
              "progressive Blake2s state ABI must be 96 bytes");

static __device__ __constant__ uint32_t kIv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

static __device__ __constant__ uint8_t kSigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

__device__ __forceinline__ uint32_t rotate_right(
    uint32_t value,
    uint32_t shift) {
#if defined(STWO_CUMETAL)
    uint32_t right;
    uint32_t left;
    const uint32_t complement = 32u - shift;
    asm("shr.b32 %0, %1, %2;" : "=r"(right) : "r"(value), "r"(shift));
    asm("shl.b32 %0, %1, %2;" : "=r"(left) : "r"(value), "r"(complement));
    return right | left;
#else
    return (value >> shift) | (value << (32u - shift));
#endif
}

#define STWO_BLAKE2S_G(r, i, a, b, c, d)                               \
    do {                                                                \
        a = a + b + message[kSigma[r][2 * i]];                          \
        d = rotate_right(d ^ a, 16);                                    \
        c += d;                                                         \
        b = rotate_right(b ^ c, 12);                                    \
        a = a + b + message[kSigma[r][2 * i + 1]];                      \
        d = rotate_right(d ^ a, 8);                                     \
        c += d;                                                         \
        b = rotate_right(b ^ c, 7);                                     \
    } while (0)

__device__ __forceinline__ void compress(
    uint32_t hash[8],
    const uint32_t message[16],
    uint64_t byte_count,
    uint32_t last_block) {
    uint32_t work[16];
#pragma unroll
    for (int index = 0; index < 8; ++index) work[index] = hash[index];
#pragma unroll
    for (int index = 0; index < 8; ++index) work[index + 8] = kIv[index];
    work[12] ^= static_cast<uint32_t>(byte_count);
    work[13] ^= static_cast<uint32_t>(byte_count >> 32);
    work[14] ^= last_block;

#pragma unroll
    for (int round = 0; round < 10; ++round) {
        STWO_BLAKE2S_G(round, 0, work[0], work[4], work[8], work[12]);
        STWO_BLAKE2S_G(round, 1, work[1], work[5], work[9], work[13]);
        STWO_BLAKE2S_G(round, 2, work[2], work[6], work[10], work[14]);
        STWO_BLAKE2S_G(round, 3, work[3], work[7], work[11], work[15]);
        STWO_BLAKE2S_G(round, 4, work[0], work[5], work[10], work[15]);
        STWO_BLAKE2S_G(round, 5, work[1], work[6], work[11], work[12]);
        STWO_BLAKE2S_G(round, 6, work[2], work[7], work[8], work[13]);
        STWO_BLAKE2S_G(round, 7, work[3], work[4], work[9], work[14]);
    }
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        hash[index] ^= work[index] ^ work[index + 8];
    }
}

#undef STWO_BLAKE2S_G

__device__ __forceinline__ void initialize(uint32_t hash[8]) {
#pragma unroll
    for (int index = 0; index < 8; ++index) hash[index] = kIv[index];
    hash[0] ^= 0x01010020u;
}

__device__ __forceinline__ void initialize_domain(
    uint32_t hash[8],
    uint32_t tag) {
    uint32_t prefix[16] = {};
    prefix[0] = tag;
    initialize(hash);
    compress(hash, prefix, kDomainPrefixBytes, 0);
}

__device__ __forceinline__ void initialize_leaf(uint32_t hash[8]) {
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        hash[index] = kLeafInitialState.words[index];
    }
}

__device__ __forceinline__ void initialize_node(uint32_t hash[8]) {
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        hash[index] = kNodeInitialState.words[index];
    }
}

__device__ __forceinline__ Hash hash_children(
    const Hash &left,
    const Hash &right) {
    uint32_t hash[8];
    uint32_t message[16];
    initialize_node(hash);
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        message[index] = left.words[index];
        message[index + 8] = right.words[index];
    }
    compress(hash, message, 128, 0xffffffffu);
    Hash result;
#pragma unroll
    for (int index = 0; index < 8; ++index) result.words[index] = hash[index];
    return result;
}

__host__ __device__ constexpr uint32_t blocks_for(uint32_t size) {
    return (size - 1) / kBlockSize + 1;
}

inline bool ranges_overlap(
    const void *left,
    size_t left_bytes,
    const void *right,
    size_t right_bytes) {
    const uintptr_t left_begin = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_begin = reinterpret_cast<uintptr_t>(right);
    if (left_bytes > UINTPTR_MAX - left_begin ||
        right_bytes > UINTPTR_MAX - right_begin) {
        return true;
    }
    return left_begin < right_begin + right_bytes &&
        right_begin < left_begin + left_bytes;
}

}  // namespace stwo::cuda::blake2s

#endif
