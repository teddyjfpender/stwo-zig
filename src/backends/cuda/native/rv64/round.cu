#include "round.cuh"
#include "custody.cuh"
namespace stwo::cuda::rv64 {
__global__ void round_init_kernel(uint32_t* state, const uint32_t* seed, const uint32_t* claim,
                                  uint32_t variables) {
    initialize_round(reinterpret_cast<RoundState*>(state), seed, from_words(claim), variables);
}
__global__ void round_advance_kernel(uint32_t* state, uint32_t expected, StwoRv64Plane raw,
                                     const uint32_t* point, uint32_t variables,
                                     uint32_t* record) {
    // Subsequent already-enqueued folds must never read an uninitialized
    // challenge when a device-side pole/order error aborts this round.
    for (uint32_t i = 0; i < round_record_words; ++i) record[i] = 0;
    record[41] = UINT32_MAX;
    auto* owner = reinterpret_cast<RoundState*>(state);
    if (owner->status != round_ok) return;
    if (owner->variables != variables) {
        owner->status = round_order;
        return;
    }
    advance_round(owner, expected,
                  {load(raw.words, raw.stride, 0), load(raw.words, raw.stride, 1)},
                  from_words(point + 8 * expected), reinterpret_cast<RoundRecord*>(record));
}
}  // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_sumcheck_init_on(void* context, uint32_t lane, uint32_t* state,
                                          const uint32_t* seed, const uint32_t* claim,
                                          uint32_t variables) {
    if (!variables || variables > 27) return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.range(state, round_state_words, true) || !c.range(seed, 9, false) ||
        !c.range(claim, 8, false))
        return c.status;
    round_init_kernel<<<1, 1, 0, c.stream>>>(state, seed, claim, variables);
    return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_sumcheck_round_on(void* context, uint32_t lane, uint32_t* state,
                                           uint32_t variables, uint32_t expected,
                                           StwoRv64Plane raw, const uint32_t* point,
                                           uint32_t* record) {
    if (!variables || variables > 27 || expected >= variables)
        return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.range(state, round_state_words, true) || !c.plane(raw, 2, 8, false) ||
        !c.range(point, 8ull * variables, false) || !c.range(record, round_record_words, true))
        return c.status;
    round_advance_kernel<<<1, 1, 0, c.stream>>>(state, expected, raw, point, variables, record);
    return int(cudaPeekAtLastError());
}
namespace stwo::cuda::rv64 {
__global__ void pack_mask_kernel(StwoRv64Plane n, StwoRv64Plane d, uint32_t* output) {
    const uint32_t c = threadIdx.x;
    if (c >= 8) return;
    output[c] = n.words[c * n.stride];
    output[8 + c] = n.words[c * n.stride + 1];
    output[16 + c] = d.words[c * d.stride];
    output[24 + c] = d.words[c * d.stride + 1];
}
}  // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_gkr_pack_mask_on(void* context, uint32_t lane, StwoRv64Plane n,
                                          StwoRv64Plane d, uint32_t* output) {
    Custody c(context, lane);
    if (!c.plane(n, 2, 8, false) || !c.plane(d, 2, 8, false) || !c.range(output, 32, true))
        return c.status;
    pack_mask_kernel<<<1, 32, 0, c.stream>>>(n, d, output);
    return int(cudaPeekAtLastError());
}
