#include "resident_pow.cuh"

#include <cuda_runtime.h>
#include <stdint.h>

#include "blake2s.cuh"

namespace {

constexpr uint32_t POW_PREFIX = 0x12345678U;
constexpr uint32_t POW_BLOCK_SIZE = 256U;
constexpr uint32_t POW_GRID_SIZE = 1024U;
constexpr uint32_t POW_MIN_BLOCKS_PER_SM = 6U;
constexpr int POW_PRIMARY_ROUND_UNROLL = 2;
constexpr int POW_FALLBACK_ROUND_UNROLL = 5;
static_assert(POW_PRIMARY_ROUND_UNROLL < POW_FALLBACK_ROUND_UNROLL,
              "PoW u2 must remain the compiled primary");

// SIMD grind lattice (crates/stwo/src/prover/backend/simd/grind.rs). The
// reference scans nonces of the form (hi << 32) | low with 0 <= low < 2^20,
// hi ascending and low ascending within each hi, and returns the first hit.
// Because low < 2^20 < 2^32, that (hi, low) scan order IS numeric order on
// the lattice values, so the reference answer is exactly the numeric minimum
// of the qualifying lattice nonces. This kernel therefore enumerates a linear
// index i, maps it monotonically onto the lattice, and takes an atomicMin of
// the MAPPED nonce: the published minimum is byte-identical to SIMD's result.
constexpr uint32_t POW_GRIND_LOW_BITS = 20U;
constexpr unsigned long long POW_GRIND_LOW_MASK =
    (1ULL << POW_GRIND_LOW_BITS) - 1ULL;
// SIMD asserts the found hi is < 2^31 - 1 (the M31 prime). Mirror that bound
// as the give-up limit: indices span [0, P << 20) ~ 2^51, astronomically more
// than any realistic grind (pow_bits <= 32 needs ~2^32 attempts). On
// exhaustion best_nonce stays UINT64_MAX (not a lattice value, since lattice
// values have zero bits 20..31) and the published nonce fails verification
// downstream: fail-closed, never a silent wrap.
constexpr unsigned long long POW_INDEX_LIMIT =
    static_cast<unsigned long long>(0x7FFFFFFFU) << POW_GRIND_LOW_BITS;

// Monotone index -> lattice nonce map: i -> ((i >> 20) << 32) | (i & 0xFFFFF).
// Strictly increasing in i (the hi field takes the index's high bits, the low
// field its low 20 bits, and nonce bits 20..31 are always zero), so numeric
// comparisons on mapped nonces order exactly like the underlying indices.
__device__ __forceinline__ unsigned long long pow_index_to_nonce(
    unsigned long long index) {
  return ((index >> POW_GRIND_LOW_BITS) << 32U) | (index & POW_GRIND_LOW_MASK);
}

// Fixed 40-byte Blake2s candidate block, shared semantically with the legacy
// grind kernel but kept local so the persistent loop stays fully in registers.
static __device__ __constant__ uint32_t POW_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

static __device__ __constant__ uint8_t POW_SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

struct PowPrefixWords {
  uint32_t w0;
  uint32_t w1;
  uint32_t w2;
  uint32_t w3;
  uint32_t w4;
  uint32_t w5;
  uint32_t w6;
  uint32_t w7;
};

__device__ __forceinline__ uint32_t pow_message_word(
    const Blake2sHash &prefix,
    unsigned long long nonce,
    uint32_t index) {
  // Decode the fixed 40-byte block in place. A per-thread m[16] array becomes
  // local memory under the runtime sigma index. The block-shared prefix plus
  // two nonce registers keep the candidate loop stack- and local-traffic-free.
  if (index < 8U) {
    return prefix.s[index];
  }
  if (index == 8U) {
    return static_cast<uint32_t>(nonce);
  }
  if (index == 9U) {
    return static_cast<uint32_t>(nonce >> 32U);
  }
  return 0U;
}

template <uint32_t INDEX>
__device__ __forceinline__ uint32_t fixed_message_word(
    const PowPrefixWords &prefix,
    unsigned long long nonce) {
  if constexpr (INDEX == 0U) return prefix.w0;
  if constexpr (INDEX == 1U) return prefix.w1;
  if constexpr (INDEX == 2U) return prefix.w2;
  if constexpr (INDEX == 3U) return prefix.w3;
  if constexpr (INDEX == 4U) return prefix.w4;
  if constexpr (INDEX == 5U) return prefix.w5;
  if constexpr (INDEX == 6U) return prefix.w6;
  if constexpr (INDEX == 7U) return prefix.w7;
  if constexpr (INDEX == 8U) return static_cast<uint32_t>(nonce);
  if constexpr (INDEX == 9U) return static_cast<uint32_t>(nonce >> 32U);
  return 0U;
}

#define POW_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define POW_G(r, i, a, b, c, d)                                  \
  do {                                                            \
    a = a + b + pow_message_word(                                 \
                      prefix, nonce,                              \
                      POW_SIGMA[r][2 * i + 0]);                   \
    d = POW_ROTR32(d ^ a, 16);                                    \
    c = c + d;                                                    \
    b = POW_ROTR32(b ^ c, 12);                                    \
    a = a + b + pow_message_word(                                 \
                      prefix, nonce,                              \
                      POW_SIGMA[r][2 * i + 1]);                   \
    d = POW_ROTR32(d ^ a, 8);                                     \
    c = c + d;                                                    \
    b = POW_ROTR32(b ^ c, 7);                                     \
  } while (0)

#define POW_FIXED_G(m0, m1, a, b, c, d)                           \
  do {                                                            \
    a = a + b + fixed_message_word<m0>(prefix, nonce);            \
    d = POW_ROTR32(d ^ a, 16);                                    \
    c = c + d;                                                    \
    b = POW_ROTR32(b ^ c, 12);                                    \
    a = a + b + fixed_message_word<m1>(prefix, nonce);            \
    d = POW_ROTR32(d ^ a, 8);                                     \
    c = c + d;                                                    \
    b = POW_ROTR32(b ^ c, 7);                                     \
  } while (0)

#define POW_FIXED_ROUND(                                           \
    m00, m01, m10, m11, m20, m21, m30, m31,                       \
    m40, m41, m50, m51, m60, m61, m70, m71)                       \
  do {                                                            \
    POW_FIXED_G(m00, m01, v[0], v[4], v[8], v[12]);               \
    POW_FIXED_G(m10, m11, v[1], v[5], v[9], v[13]);               \
    POW_FIXED_G(m20, m21, v[2], v[6], v[10], v[14]);              \
    POW_FIXED_G(m30, m31, v[3], v[7], v[11], v[15]);              \
    POW_FIXED_G(m40, m41, v[0], v[5], v[10], v[15]);              \
    POW_FIXED_G(m50, m51, v[1], v[6], v[11], v[12]);              \
    POW_FIXED_G(m60, m61, v[2], v[7], v[8], v[13]);               \
    POW_FIXED_G(m70, m71, v[3], v[4], v[9], v[14]);               \
  } while (0)

__device__ __forceinline__ void initialize_candidate_state(uint32_t (&v)[16]) {
  v[0] = POW_IV[0] ^ 0x01010020U;
#pragma unroll
  for (uint32_t i = 1U; i < 8U; ++i) {
    v[i] = POW_IV[i];
  }
#pragma unroll
  for (uint32_t i = 0U; i < 8U; ++i) {
    v[i + 8U] = POW_IV[i];
  }
  v[12] ^= 40U;
  v[14] ^= 0xffffffffU;
}

__device__ __forceinline__ uint32_t fixed_candidate_hash_word(
    const PowPrefixWords &prefix,
    unsigned long long nonce) {
  uint32_t v[16];
  initialize_candidate_state(v);

  // Five bounded two-round packets keep the sigma schedule compile-time while
  // preventing ptxas from scheduling all ten rounds as one 255-register body.
#pragma unroll 1
  for (uint32_t pair = 0U; pair < 5U; ++pair) {
    switch (pair) {
      case 0U:
        POW_FIXED_ROUND(0, 1, 2, 3, 4, 5, 6, 7,
                        8, 9, 10, 11, 12, 13, 14, 15);
        POW_FIXED_ROUND(14, 10, 4, 8, 9, 15, 13, 6,
                        1, 12, 0, 2, 11, 7, 5, 3); break;
      case 1U:
        POW_FIXED_ROUND(11, 8, 12, 0, 5, 2, 15, 13,
                        10, 14, 3, 6, 7, 1, 9, 4);
        POW_FIXED_ROUND(7, 9, 3, 1, 13, 12, 11, 14,
                        2, 6, 5, 10, 4, 0, 15, 8); break;
      case 2U:
        POW_FIXED_ROUND(9, 0, 5, 7, 2, 4, 10, 15,
                        14, 1, 11, 12, 6, 8, 3, 13);
        POW_FIXED_ROUND(2, 12, 6, 10, 0, 11, 8, 3,
                        4, 13, 7, 5, 15, 14, 1, 9); break;
      case 3U:
        POW_FIXED_ROUND(12, 5, 1, 15, 14, 13, 4, 10,
                        0, 7, 6, 3, 9, 2, 8, 11);
        POW_FIXED_ROUND(13, 11, 7, 14, 12, 1, 3, 9,
                        5, 0, 15, 4, 8, 6, 2, 10); break;
      default:
        POW_FIXED_ROUND(6, 15, 14, 9, 11, 3, 0, 8,
                        12, 2, 13, 7, 1, 4, 10, 5);
        POW_FIXED_ROUND(10, 2, 8, 4, 7, 6, 1, 5,
                        15, 11, 9, 14, 3, 12, 13, 0); break;
    }
  }
  return (POW_IV[0] ^ 0x01010020U) ^ v[0] ^ v[8];
}

template <int ROUND_UNROLL>
__device__ __forceinline__ uint32_t candidate_hash_word(
    const Blake2sHash &prefix,
    unsigned long long nonce) {
  uint32_t v[16];
  initialize_candidate_state(v);

#pragma unroll ROUND_UNROLL
  for (uint32_t round = 0U; round < 10U; ++round) {
    POW_G(round, 0, v[0], v[4], v[8], v[12]);
    POW_G(round, 1, v[1], v[5], v[9], v[13]);
    POW_G(round, 2, v[2], v[6], v[10], v[14]);
    POW_G(round, 3, v[3], v[7], v[11], v[15]);
    POW_G(round, 4, v[0], v[5], v[10], v[15]);
    POW_G(round, 5, v[1], v[6], v[11], v[12]);
    POW_G(round, 6, v[2], v[7], v[8], v[13]);
    POW_G(round, 7, v[3], v[4], v[9], v[14]);
  }
  return (POW_IV[0] ^ 0x01010020U) ^ v[0] ^ v[8];
}

__device__ __forceinline__ uint32_t trailing_zeros(uint32_t value) {
  return value == 0U ? 32U : static_cast<uint32_t>(__clz(__brev(value)));
}

__global__ void pow_prefix_digest(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t *prefix_digest) {
  if (blockIdx.x != 0U || threadIdx.x != 0U) {
    return;
  }
  uint8_t prefix_input[52] = {0};
  prefix_input[0] = static_cast<uint8_t>(POW_PREFIX);
  prefix_input[1] = static_cast<uint8_t>(POW_PREFIX >> 8U);
  prefix_input[2] = static_cast<uint8_t>(POW_PREFIX >> 16U);
  prefix_input[3] = static_cast<uint8_t>(POW_PREFIX >> 24U);
  const uint8_t *digest = reinterpret_cast<const uint8_t *>(transcript_state);
#pragma unroll
  for (uint32_t i = 0; i < 32U; ++i) {
    prefix_input[16U + i] = digest[i];
  }
  prefix_input[48] = static_cast<uint8_t>(pow_bits);
  prefix_input[49] = static_cast<uint8_t>(pow_bits >> 8U);
  prefix_input[50] = static_cast<uint8_t>(pow_bits >> 16U);
  prefix_input[51] = static_cast<uint8_t>(pow_bits >> 24U);
  Blake2sHash value;
  stwo_blake2s_hash2_device(prefix_input, 52U, nullptr, 0U, &value);
#pragma unroll
  for (uint32_t i = 0; i < 8U; ++i) {
    prefix_digest[i] = value.s[i];
  }
}

template <int ROUND_UNROLL>
__global__ __launch_bounds__(POW_BLOCK_SIZE, POW_MIN_BLOCKS_PER_SM)
void persistent_pow_search(
    const uint32_t *prefix_digest_words,
    uint32_t pow_bits,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce) {
  __shared__ Blake2sHash prefixed_digest;
  if (threadIdx.x < 8U) {
    prefixed_digest.s[threadIdx.x] = prefix_digest_words[threadIdx.x];
  }
  __syncthreads();

  const PowPrefixWords prefix{
      prefixed_digest.s[0], prefixed_digest.s[1],
      prefixed_digest.s[2], prefixed_digest.s[3],
      prefixed_digest.s[4], prefixed_digest.s[5],
      prefixed_digest.s[6], prefixed_digest.s[7]};

  const unsigned long long worker =
      static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x;
  const unsigned long long stride =
      static_cast<unsigned long long>(gridDim.x) * blockDim.x;
  // Workers stride over the linear INDEX space; every hashed candidate is the
  // mapped lattice nonce, and best_nonce always holds a mapped value (or the
  // UINT64_MAX sentinel). Because the map is strictly monotone, comparing a
  // mapped candidate against best is equivalent to comparing indices, so the
  // early-exit reasoning below is unchanged from the pre-lattice kernel.
  // index + stride cannot overflow: index < POW_INDEX_LIMIT ~ 2^51 and
  // stride = gridDim.x * blockDim.x = 2^18.
  unsigned long long index = worker;
  while (index < POW_INDEX_LIMIT) {
    const unsigned long long candidate = pow_index_to_nonce(index);
    // An atomic read prevents a worker from terminating on an out-of-date
    // larger bound. A stale smaller bound is impossible because best only falls.
    const unsigned long long best = atomicAdd(best_nonce, 0ULL);
    if (candidate >= best) {
      break;
    }

    uint32_t hash_word;
    if constexpr (ROUND_UNROLL == POW_PRIMARY_ROUND_UNROLL) {
      hash_word = fixed_candidate_hash_word(prefix, candidate);
    } else {
      hash_word = candidate_hash_word<ROUND_UNROLL>(prefixed_digest, candidate);
    }
    if (trailing_zeros(hash_word) >= pow_bits) {
      atomicMin(best_nonce, candidate);
    }

    index += stride;
  }

  // Every worker exhausts its index residue class for all lattice nonces below
  // the observed minimum. The last block to retire therefore knows every
  // lattice candidate below the final atomic minimum was checked, and alone
  // publishes the transcript nonce -- the numerically smallest qualifying
  // lattice nonce, i.e. exactly the SIMD grind's answer.
  __syncthreads();
  if (threadIdx.x == 0U) {
    __threadfence();
    const uint32_t completed = atomicAdd(completed_blocks, 1U) + 1U;
    if (completed == gridDim.x) {
      const unsigned long long nonce = atomicAdd(best_nonce, 0ULL);
      transcript_nonce[0] = static_cast<uint32_t>(nonce);
      transcript_nonce[1] = static_cast<uint32_t>(nonce >> 32U);
      __threadfence();
    }
  }
}

template <int ROUND_UNROLL>
__global__ __launch_bounds__(POW_BLOCK_SIZE, POW_MIN_BLOCKS_PER_SM)
void persistent_pow_rank_tile_search(
    const uint32_t *prefix_digest_words,
    uint32_t pow_bits,
    uint32_t rank_count,
    uint32_t rank,
    unsigned long long tile_start,
    unsigned long long tile_end,
    unsigned long long *best_nonce) {
  __shared__ Blake2sHash prefixed_digest;
  if (threadIdx.x < 8U) {
    prefixed_digest.s[threadIdx.x] = prefix_digest_words[threadIdx.x];
  }
  __syncthreads();

  const PowPrefixWords prefix{
      prefixed_digest.s[0], prefixed_digest.s[1],
      prefixed_digest.s[2], prefixed_digest.s[3],
      prefixed_digest.s[4], prefixed_digest.s[5],
      prefixed_digest.s[6], prefixed_digest.s[7]};

  const unsigned long long local_worker =
      static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x;
  const unsigned long long workers_per_rank =
      static_cast<unsigned long long>(gridDim.x) * blockDim.x;
  const unsigned long long stride =
      workers_per_rank * static_cast<unsigned long long>(rank_count);
  const unsigned long long residue =
      static_cast<unsigned long long>(rank) * workers_per_rank + local_worker;
  const unsigned long long tile_residue = tile_start % stride;
  const unsigned long long delta =
      residue >= tile_residue
          ? residue - tile_residue
          : stride - (tile_residue - residue);
  const unsigned long long tile_length = tile_end - tile_start;
  unsigned long long index =
      delta < tile_length ? tile_start + delta : tile_end;

  while (index < tile_end) {
    const unsigned long long candidate = pow_index_to_nonce(index);
    const unsigned long long best = atomicAdd(best_nonce, 0ULL);
    if (candidate >= best) {
      break;
    }

    uint32_t hash_word;
    if constexpr (ROUND_UNROLL == POW_PRIMARY_ROUND_UNROLL) {
      hash_word = fixed_candidate_hash_word(prefix, candidate);
    } else {
      hash_word = candidate_hash_word<ROUND_UNROLL>(prefixed_digest, candidate);
    }
    if (trailing_zeros(hash_word) >= pow_bits) {
      atomicMin(best_nonce, candidate);
    }
    if (stride >= tile_end - index) {
      break;
    }
    index += stride;
  }
}

}  // namespace

extern "C" int stwo_blake2s_pow_persistent_on(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce,
    void *stream_raw) {
  if (transcript_state == nullptr || prefix_digest == nullptr ||
      best_nonce == nullptr || completed_blocks == nullptr ||
      transcript_nonce == nullptr || stream_raw == nullptr || pow_bits > 32U) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  pow_prefix_digest<<<1U, 1U, 0,
                      reinterpret_cast<cudaStream_t>(stream_raw)>>>(
      transcript_state, pow_bits, prefix_digest);
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    return static_cast<int>(error);
  }
  const cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  persistent_pow_search<POW_PRIMARY_ROUND_UNROLL>
      <<<POW_GRID_SIZE, POW_BLOCK_SIZE, 0, stream>>>(
      prefix_digest, pow_bits, best_nonce, completed_blocks,
      transcript_nonce);
  error = cudaGetLastError();
  if (error != cudaErrorLaunchOutOfResources) {
    return static_cast<int>(error);
  }

  // The u5 body is compiled into the same artifact as a conservative fallback.
  // Both instantiations execute identical operations and share the same ordered
  // completed-block publication proof; only compiler scheduling differs.
  persistent_pow_search<POW_FALLBACK_ROUND_UNROLL>
      <<<POW_GRID_SIZE, POW_BLOCK_SIZE, 0, stream>>>(
      prefix_digest, pow_bits, best_nonce, completed_blocks,
      transcript_nonce);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_pow_rank_tile_on(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t rank_count,
    uint32_t rank,
    unsigned long long tile_start,
    unsigned long long tile_end,
    uint32_t grid_blocks,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    void *stream_raw) {
  if (transcript_state == nullptr || prefix_digest == nullptr ||
      best_nonce == nullptr || stream_raw == nullptr || pow_bits > 32U ||
      rank_count == 0U || rank >= rank_count || tile_start >= tile_end ||
      tile_end > POW_INDEX_LIMIT || grid_blocks == 0U ||
      grid_blocks > 0x7fffffffU) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  const unsigned long long workers_per_rank =
      static_cast<unsigned long long>(grid_blocks) * POW_BLOCK_SIZE;
  if (static_cast<unsigned long long>(rank_count) >
      ~0ULL / workers_per_rank) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  const cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  pow_prefix_digest<<<1U, 1U, 0, stream>>>(
      transcript_state, pow_bits, prefix_digest);
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    return static_cast<int>(error);
  }
  persistent_pow_rank_tile_search<POW_PRIMARY_ROUND_UNROLL>
      <<<grid_blocks, POW_BLOCK_SIZE, 0, stream>>>(
      prefix_digest, pow_bits, rank_count, rank, tile_start, tile_end,
      best_nonce);
  error = cudaGetLastError();
  if (error != cudaErrorLaunchOutOfResources) {
    return static_cast<int>(error);
  }
  persistent_pow_rank_tile_search<POW_FALLBACK_ROUND_UNROLL>
      <<<grid_blocks, POW_BLOCK_SIZE, 0, stream>>>(
      prefix_digest, pow_bits, rank_count, rank, tile_start, tile_end,
      best_nonce);
  return static_cast<int>(cudaGetLastError());
}
