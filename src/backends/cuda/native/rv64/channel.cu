// Native raw-Blake/mod-M31 OM31 channel. All feedback stays on the device.
#include "channel.h"
#include "custody.cuh"
#include "transcript/state.cuh"
namespace stwo::cuda::rv64 {
namespace t = stwo::cuda::transcript;
__global__ void channel_init(uint32_t *words, const uint32_t *seed,
                             uint64_t chain) {
  auto *s = t::as_state(words);
  t::copy_words(s->digest, seed, 8);
  s->draws = seed[8];
  s->cursor = 0;
  s->status = s->draws <= t::kMaximumSeedDraws ? t::kOk : t::kInvalidSeed;
  s->reserved = 0;
  s->chain = chain;
  s->padding[0] = s->padding[1] = 0;
}
__global__ void channel_mix(uint32_t *words, uint32_t step, uint64_t chain,
                            uint64_t next, const uint32_t *input,
                            uint32_t count, uint32_t field,
                            uint32_t *boundary) {
  auto *s = t::as_state(words);
  if (t::begin_step(s, step, chain)) {
    if (s->reserved != 0 || step == UINT32_MAX)
      s->status = t::kOrder;
    if (field)
      for (uint32_t i = 0; i < count; ++i)
        if (input[i] >= t::kM31Prime)
          s->status = t::kInvalidField;
    if (s->status == t::kOk)
      t::update_digest(s, input, count);
  }
  t::finish_step(s, next, boundary);
}
__global__ void channel_draw(uint32_t *words, uint32_t step, uint64_t chain,
                             uint64_t next, uint32_t count, uint32_t *output,
                             uint32_t *boundary) {
  auto *s = t::as_state(words);
  __shared__ uint32_t digest[8], first_draw;
  __shared__ bool valid;
  if (threadIdx.x == 0) {
    valid = t::begin_step(s, step, chain);
    if (valid && (s->reserved != 0 || step == UINT32_MAX ||
                  s->draws > UINT32_MAX - count)) {
      s->status = t::kOrder;
      valid = false;
    }
    first_draw = s->draws;
  }
  if (threadIdx.x < 8)
    digest[threadIdx.x] = s->digest[threadIdx.x];
  __syncthreads();
  // Counter-based draws are independent, including the final partial batch.
  // Keep the shared channel mutation on one thread after every draw completes.
  for (uint32_t i = threadIdx.x; i < count; i += blockDim.x) {
    if (valid) {
      const auto raw = t::hash_draw(digest, first_draw + i);
      for (uint32_t c = 0; c < 8; ++c)
        output[8 * i + c] = t::reduce_m31_word(raw.words[c]);
    } else {
      for (uint32_t c = 0; c < 8; ++c)
        output[8 * i + c] = 0;
    }
  }
  __syncthreads();
  if (threadIdx.x == 0) {
    if (valid)
      s->draws += count;
    t::finish_step(s, next, boundary);
  }
}
inline bool channel_state(Custody &c, uint32_t *state) {
  if (reinterpret_cast<uintptr_t>(state) % alignof(t::State)) {
    c.status = int(cudaErrorInvalidValue);
    return false;
  }
  return c.range(state, t::kStateWords, true);
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_channel_init_on(void *ctx, uint32_t lane,
                                         uint32_t *state, const uint32_t *seed,
                                         uint64_t chain) {
  Custody c(ctx, lane);
  if (!channel_state(c, state) || !c.range(seed, 9, false))
    return c.status;
  channel_init<<<1, 1, 0, c.stream>>>(state, seed, chain);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_channel_mix_on(void *ctx, uint32_t lane,
                                        uint32_t *state, uint32_t step,
                                        uint64_t chain, uint64_t next,
                                        const uint32_t *input, uint32_t count,
                                        uint32_t field, uint32_t *boundary) {
  if (count > t::kMaximumMixWords || field > 1)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!channel_state(c, state) || (count && !c.range(input, count, false)) ||
      !c.range(boundary, t::kStateWords, true))
    return c.status;
  channel_mix<<<1, 1, 0, c.stream>>>(state, step, chain, next, input, count,
                                     field, boundary);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_channel_draw_on(void *ctx, uint32_t lane,
                                         uint32_t *state, uint32_t step,
                                         uint64_t chain, uint64_t next,
                                         uint32_t count, uint32_t *output,
                                         uint32_t *boundary) {
  if (!count || count > 1u << 20)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!channel_state(c, state) || !c.range(output, uint64_t(count) * 8, true) ||
      !c.range(boundary, t::kStateWords, true))
    return c.status;
  channel_draw<<<1, 128, 0, c.stream>>>(state, step, chain, next, count, output,
                                        boundary);
  return int(cudaPeekAtLastError());
}
