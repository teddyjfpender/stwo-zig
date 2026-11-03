#include "composition_finalize.h"
#include "custody.cuh"
extern "C" int
stwo_ntt_b2n_om31_composition_split_on(uint32_t *, size_t, uint32_t *, size_t,
                                       uint32_t, uint32_t, const uint32_t *,
                                       uint32_t, void *, uint32_t *);
extern "C" int
stwo_rv64_composition_finalize_on(void *ctx, uint32_t lane, uint32_t *input,
                                  uint32_t *output, uint32_t log,
                                  uint32_t depth, const uint32_t *twiddles,
                                  uint32_t twiddle_words, uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches)
    *launches = 0;
  if (!launches || log < 3 || log > 28 || depth < 1 || depth > 2 ||
      log <= depth + 1 || twiddle_words < (1u << (log - 1)))
    return int(cudaErrorInvalidValue);
  const uint64_t words = uint64_t(8) << log;
  Custody c(ctx, lane);
  if (!c.range(input, words, true) || !c.range(output, words, true) ||
      !c.range(twiddles, twiddle_words, false))
    return c.status;
  return stwo_ntt_b2n_om31_composition_split_on(
      input, words, output, words, log, depth, twiddles, twiddle_words,
      c.stream, launches);
}
