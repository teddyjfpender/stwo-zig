#include "device_transcript.cuh"

#include <cuda_runtime.h>

#include "blake2s.cuh"

namespace {

constexpr uint32_t M31_P = 0x7fffffffU;
constexpr uint32_t POW_PREFIX = 0x12345678U;
constexpr uint32_t STATE_WORDS = 16U;
constexpr uint32_t MAX_SEED_DRAWS = 1U << 20U;

enum TranscriptStatus : uint32_t {
  STATUS_OK = 0U,
  STATUS_ORDER = 1U,
  STATUS_REJECTION_LIMIT = 2U,
  STATUS_INVALID_POW = 3U,
  STATUS_INVALID_FIELD = 4U,
  STATUS_INVALID_SEED = 5U,
};

struct TranscriptState {
  uint32_t digest[8];
  uint32_t n_draws;
  uint32_t cursor;
  uint32_t status;
  uint32_t reserved;
  uint64_t chain;
  uint32_t padding[2];
};

static_assert(sizeof(TranscriptState) == STATE_WORDS * sizeof(uint32_t),
              "transcript state ABI must remain 16 words");

__device__ __forceinline__ TranscriptState *as_state(uint32_t *words) {
  return reinterpret_cast<TranscriptState *>(words);
}

__device__ __forceinline__ void copy_words(uint32_t *dst,
                                            const uint32_t *src,
                                            uint32_t count) {
  for (uint32_t i = 0; i < count; ++i) {
    dst[i] = src[i];
  }
}

__device__ __forceinline__ void snapshot(const TranscriptState *state,
                                          uint32_t *out) {
  copy_words(out, reinterpret_cast<const uint32_t *>(state), STATE_WORDS);
}

__device__ __forceinline__ bool begin_step(TranscriptState *state,
                                            uint32_t expected_step,
                                            uint64_t expected_chain) {
  if (state->status != STATUS_OK) {
    return false;
  }
  if (state->cursor != expected_step || state->chain != expected_chain) {
    state->status = STATUS_ORDER;
    return false;
  }
  return true;
}

__device__ __forceinline__ void finish_step(TranscriptState *state,
                                             uint64_t next_chain,
                                             uint32_t *boundary) {
  if (state->status == STATUS_OK) {
    ++state->cursor;
    state->chain = next_chain;
  }
  snapshot(state, boundary);
}

__device__ __forceinline__ void hash_digest_and_words(
    TranscriptState *state,
    const uint32_t *words,
    uint32_t n_words) {
  Blake2sHash digest;
  stwo_blake2s_hash2_device(
      reinterpret_cast<const uint8_t *>(state->digest), 32U,
      reinterpret_cast<const uint8_t *>(words),
      static_cast<size_t>(n_words) * sizeof(uint32_t), &digest);
  copy_words(state->digest, digest.s, 8U);
  state->n_draws = 0U;
}

__device__ __forceinline__ void draw_words(TranscriptState *state,
                                            uint32_t out[8]) {
  uint8_t suffix[5];
  const uint32_t counter = state->n_draws;
  suffix[0] = static_cast<uint8_t>(counter);
  suffix[1] = static_cast<uint8_t>(counter >> 8U);
  suffix[2] = static_cast<uint8_t>(counter >> 16U);
  suffix[3] = static_cast<uint8_t>(counter >> 24U);
  suffix[4] = 0U;
  Blake2sHash digest;
  stwo_blake2s_hash2_device(
      reinterpret_cast<const uint8_t *>(state->digest), 32U, suffix, 5U,
      &digest);
  copy_words(out, digest.s, 8U);
  ++state->n_draws;
}

__device__ __forceinline__ bool valid_pow(const TranscriptState *state,
                                           uint32_t pow_bits,
                                           uint64_t nonce) {
  uint8_t prefix_input[52] = {0};
  prefix_input[0] = static_cast<uint8_t>(POW_PREFIX);
  prefix_input[1] = static_cast<uint8_t>(POW_PREFIX >> 8U);
  prefix_input[2] = static_cast<uint8_t>(POW_PREFIX >> 16U);
  prefix_input[3] = static_cast<uint8_t>(POW_PREFIX >> 24U);
  const uint8_t *digest_bytes =
      reinterpret_cast<const uint8_t *>(state->digest);
  for (uint32_t i = 0; i < 32U; ++i) {
    prefix_input[16U + i] = digest_bytes[i];
  }
  prefix_input[48] = static_cast<uint8_t>(pow_bits);
  prefix_input[49] = static_cast<uint8_t>(pow_bits >> 8U);
  prefix_input[50] = static_cast<uint8_t>(pow_bits >> 16U);
  prefix_input[51] = static_cast<uint8_t>(pow_bits >> 24U);

  Blake2sHash prefixed;
  stwo_blake2s_hash2_device(prefix_input, 52U, nullptr, 0U, &prefixed);
  uint8_t nonce_bytes[8];
  for (uint32_t i = 0; i < 8U; ++i) {
    nonce_bytes[i] = static_cast<uint8_t>(nonce >> (8U * i));
  }
  Blake2sHash result;
  stwo_blake2s_hash2_device(
      reinterpret_cast<const uint8_t *>(prefixed.s), 32U, nonce_bytes, 8U,
      &result);

  uint32_t zeros = 0U;
  const uint8_t *bytes = reinterpret_cast<const uint8_t *>(result.s);
  for (uint32_t i = 0; i < 16U; ++i) {
    uint8_t value = bytes[i];
    if (value == 0U) {
      zeros += 8U;
      continue;
    }
    while ((value & 1U) == 0U) {
      ++zeros;
      value >>= 1U;
    }
    break;
  }
  return zeros >= pow_bits;
}

__global__ void transcript_init_kernel(uint32_t *state_words,
                                       const uint32_t *seed,
                                       uint32_t *seed_snapshot,
                                       uint64_t initial_chain) {
  TranscriptState *state = as_state(state_words);
  if (seed == nullptr) {
    for (uint32_t i = 0; i < 8U; ++i) {
      state->digest[i] = 0U;
    }
    state->n_draws = 0U;
  } else {
    copy_words(state->digest, seed, 8U);
    state->n_draws = seed[8];
    copy_words(seed_snapshot, seed, 9U);
  }
  state->cursor = 0U;
  state->status =
      state->n_draws <= MAX_SEED_DRAWS ? STATUS_OK : STATUS_INVALID_SEED;
  state->reserved = 0U;
  state->chain = initial_chain;
  state->padding[0] = 0U;
  state->padding[1] = 0U;
}

}  // namespace

extern "C" __global__ void stwo_gpu_lab_blake2s_transcript_mix_words(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *source,
    uint32_t n_words,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot) {
  TranscriptState *state = as_state(state_words);
  if (begin_step(state, expected_step, expected_chain)) {
    copy_words(input_snapshot, source, n_words);
    if (validate_m31) {
      for (uint32_t i = 0; i < n_words; ++i) {
        if (source[i] >= M31_P) {
          state->status = STATUS_INVALID_FIELD;
        }
      }
    }
    if (state->status == STATUS_OK) {
      hash_digest_and_words(state, source, n_words);
    }
  }
  finish_step(state, next_chain, boundary_snapshot);
}

namespace {

__global__ void transcript_absorb_pow_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *nonce_words,
    uint32_t pow_bits,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot) {
  TranscriptState *state = as_state(state_words);
  if (begin_step(state, expected_step, expected_chain)) {
    copy_words(input_snapshot, nonce_words, 2U);
    const uint64_t nonce = static_cast<uint64_t>(nonce_words[0]) |
                           (static_cast<uint64_t>(nonce_words[1]) << 32U);
    if (!valid_pow(state, pow_bits, nonce)) {
      state->status = STATUS_INVALID_POW;
    } else {
      hash_digest_and_words(state, nonce_words, 2U);
    }
  }
  finish_step(state, next_chain, boundary_snapshot);
}

__global__ void transcript_draw_u32s_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
  TranscriptState *state = as_state(state_words);
  if (begin_step(state, expected_step, expected_chain)) {
    uint32_t words[8];
    draw_words(state, words);
    copy_words(output, words, 8U);
    copy_words(output_snapshot, words, 8U);
  }
  finish_step(state, next_chain, boundary_snapshot);
}

}  // namespace

extern "C" __global__ void stwo_gpu_lab_blake2s_transcript_draw_secure(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t n_felts,
    uint32_t max_rejection_rounds,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
  TranscriptState *state = as_state(state_words);
  if (begin_step(state, expected_step, expected_chain)) {
    uint32_t produced = 0U;
    const uint32_t target_words = 4U * n_felts;
    while (produced < target_words && state->status == STATUS_OK) {
      bool accepted = false;
      uint32_t words[8];
      for (uint32_t attempt = 0; attempt < max_rejection_rounds; ++attempt) {
        draw_words(state, words);
        accepted = true;
        for (uint32_t i = 0; i < 8U; ++i) {
          if (words[i] >= 2U * M31_P) {
            accepted = false;
          }
        }
        if (accepted) {
          break;
        }
      }
      if (!accepted) {
        state->status = STATUS_REJECTION_LIMIT;
        break;
      }
      for (uint32_t i = 0; i < 8U && produced < target_words; ++i) {
        const uint32_t reduced =
            words[i] >= M31_P ? words[i] - M31_P : words[i];
        output[produced] = reduced;
        output_snapshot[produced] = reduced;
        ++produced;
      }
    }
  }
  finish_step(state, next_chain, boundary_snapshot);
}

namespace {

__global__ void transcript_draw_queries_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t log_domain_size,
    uint32_t n_queries,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
  TranscriptState *state = as_state(state_words);
  if (begin_step(state, expected_step, expected_chain)) {
    const uint32_t mask =
        log_domain_size == 0U ? 0U : ((1U << log_domain_size) - 1U);
    uint32_t produced = 0U;
    while (produced < n_queries) {
      uint32_t words[8];
      draw_words(state, words);
      for (uint32_t i = 0; i < 8U && produced < n_queries; ++i) {
        const uint32_t query = words[i] & mask;
        output[produced] = query;
        output_snapshot[produced] = query;
        ++produced;
      }
    }
  }
  finish_step(state, next_chain, boundary_snapshot);
}

}  // namespace

extern "C" int stwo_blake2s_transcript_init_on(
    uint32_t *state,
    const uint32_t *seed,
    uint32_t *seed_snapshot,
    uint64_t initial_chain,
    void *stream_raw) {
  if (state == nullptr || (seed != nullptr && seed_snapshot == nullptr)) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  transcript_init_kernel<<<1, 1, 0, stream>>>(state, seed, seed_snapshot,
                                              initial_chain);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_transcript_mix_words_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *source,
    uint32_t n_words,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream_raw) {
  if (state == nullptr || source == nullptr || n_words == 0U ||
      input_snapshot == nullptr || boundary_snapshot == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  stwo_gpu_lab_blake2s_transcript_mix_words<<<1, 1, 0, stream>>>(
      state, expected_step, expected_chain, next_chain, source, n_words,
      validate_m31, input_snapshot, boundary_snapshot);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_transcript_absorb_pow_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *nonce_words,
    uint32_t pow_bits,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream_raw) {
  if (state == nullptr || nonce_words == nullptr || pow_bits > 128U ||
      input_snapshot == nullptr || boundary_snapshot == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  transcript_absorb_pow_kernel<<<1, 1, 0, stream>>>(
      state, expected_step, expected_chain, next_chain, nonce_words, pow_bits,
      input_snapshot, boundary_snapshot);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_transcript_draw_u32s_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream_raw) {
  if (state == nullptr || output == nullptr || output_snapshot == nullptr ||
      boundary_snapshot == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  transcript_draw_u32s_kernel<<<1, 1, 0, stream>>>(
      state, expected_step, expected_chain, next_chain, output, output_snapshot,
      boundary_snapshot);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_transcript_draw_secure_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t n_felts,
    uint32_t max_rejection_rounds,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream_raw) {
  if (state == nullptr || n_felts == 0U || max_rejection_rounds == 0U ||
      output == nullptr || output_snapshot == nullptr ||
      boundary_snapshot == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  stwo_gpu_lab_blake2s_transcript_draw_secure<<<1, 1, 0, stream>>>(
      state, expected_step, expected_chain, next_chain, n_felts,
      max_rejection_rounds, output, output_snapshot, boundary_snapshot);
  return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_blake2s_transcript_draw_queries_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t log_domain_size,
    uint32_t n_queries,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream_raw) {
  if (state == nullptr || log_domain_size >= 32U || n_queries == 0U ||
      output == nullptr || output_snapshot == nullptr ||
      boundary_snapshot == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  transcript_draw_queries_kernel<<<1, 1, 0, stream>>>(
      state, expected_step, expected_chain, next_chain, log_domain_size,
      n_queries, output, output_snapshot, boundary_snapshot);
  return static_cast<int>(cudaGetLastError());
}
