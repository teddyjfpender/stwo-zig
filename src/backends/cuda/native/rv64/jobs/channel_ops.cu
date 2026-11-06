// Device channel ops the frozen base image does not export (M8 job runtime).
// Same transcript::State semantics as NAT/rv64/channel.cu and
// transcript/transcript.cu; enqueue only, custody-checked like every *_on API.
#include "../custody.cuh"
#include "../../transcript/state.cuh"

namespace stwo::cuda::rv64::jobs {
namespace t = stwo::cuda::transcript;
// Host Om31Channel.drawU32s: one raw (unreduced) 8-word draw, draws += 1.
// Equals transcript.cu draw_words_kernel with reserved == 0 (raw digest).
__global__ void channel_draw_raw(uint32_t *words, uint32_t step, uint64_t chain, uint64_t next,
                                 uint32_t *output, uint32_t *boundary) {
    auto *s = t::as_state(words);
    if (t::begin_step(s, step, chain)) {
        if (s->reserved != 0 || step == UINT32_MAX || s->draws == UINT32_MAX) {
            s->status = t::kOrder;
        } else {
            const auto raw = t::hash_draw(s->digest, s->draws);
            ++s->draws;
            t::copy_words(output, raw.words, 8);
        }
    }
    if (s->status != t::kOk)
        for (uint32_t i = 0; i < 8; ++i) output[i] = 0;
    t::finish_step(s, next, boundary);
}
}  // namespace stwo::cuda::rv64::jobs

extern "C" int stwo_rv64_jobs_channel_draw_raw_on(void *ctx, uint32_t lane, uint32_t *state, uint32_t step,
                                                 uint64_t chain, uint64_t next, uint32_t *output,
                                                 uint32_t *boundary) {
    using namespace stwo::cuda::rv64;
    Custody c(ctx, lane);
    if (reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State)) return int(cudaErrorInvalidValue);
    if (!c.range(state, stwo::cuda::transcript::kStateWords, true) || !c.range(output, 8, true) ||
        !c.range(boundary, stwo::cuda::transcript::kStateWords, true))
        return c.status;
    jobs::channel_draw_raw<<<1, 1, 0, c.stream>>>(state, step, chain, next, output, boundary);
    return int(cudaPeekAtLastError());
}
