// Eight-coordinate OM31 PCS primitives. No allocations, host field feedback,
// copies or joins occur in these entry points. They do not admit a proof.
#include "commitment/blake2s_protocol.cuh"
#include "common/circle_twiddle.cuh"
#include "custody.cuh"
#include "om31.cuh"
#include "pcs.h"
namespace stwo::cuda::rv64 {
__device__ __forceinline__ OM31 fri_pair(OM31 a, OM31 b, uint32_t inv_x, OM31 alpha) {
    return add(add(a, b), mul(alpha, scale(sub(a, b), inv_x)));
}
template <uint32_t Steps> __global__ void fri_fold_kernel(StwoRv64FriFold job) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= (job.count >> Steps))
        return;
    OM31 values[1u << Steps];
#pragma unroll
    for (uint32_t i = 0; i < (1u << Steps); ++i)
        values[i] = load(job.input.words, job.input.stride, (row << Steps) + i);
    OM31 alpha = from_words(job.alpha);
#pragma unroll
    for (uint32_t level = 0; level < Steps; ++level) {
#pragma unroll
        for (uint32_t i = 0; i < (1u << (Steps - 1 - level)); ++i) {
            const uint32_t index = (row << (Steps - 1 - level)) + i;
            const uint32_t inv_x =
                job.first_is_circle && level == 0
                    ? stwo::cuda::circle_twiddle(job.twiddles + job.offsets[level], index)
                    : job.twiddles[job.offsets[level] + index];
            values[i] = fri_pair(values[2 * i], values[2 * i + 1], inv_x, alpha);
        }
        alpha = mul(alpha, alpha);
    }
    if (job.accumulate_circle)
        values[0] = add(values[0], mul(alpha, load(job.output.words, job.output.stride, row)));
    store(job.output.words, job.output.stride, row, values[0]);
}
template <bool Prefixed, uint32_t LeafLog>
__global__ void fri_leaf_kernel(StwoRv64Plane input, uint32_t count, uint32_t *output) {
    using namespace stwo::cuda::blake2s;
    const uint32_t leaf = blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= (count >> LeafLog))
        return;
    uint32_t hash[8];
    initialize_leaf_for<Prefixed>(hash);
    constexpr uint32_t words = 8u << LeafLog;
#pragma unroll
    for (uint32_t block = 0; block < (words + 15) / 16; ++block) {
        uint32_t message[16]{};
#pragma unroll
        for (uint32_t j = 0; j < 16; ++j) {
            const uint32_t at = 16 * block + j;
            if (at < words)
                message[j] =
                    input.words[uint64_t(at % 8) * input.stride + (leaf << LeafLog) + at / 8];
        }
        const uint32_t consumed = (16 * (block + 1) < words) ? 16 * (block + 1) : words;
        compress(hash, message, (Prefixed ? kDomainPrefixBytes : 0) + 4ull * consumed,
                 consumed == words ? 0xffffffffu : 0);
    }
#pragma unroll
    for (uint32_t c = 0; c < 8; ++c)
        output[uint64_t(leaf) * 8 + c] = hash[c];
}
template <bool Prefixed>
int launch_leaves(Custody &c, StwoRv64Plane input, uint32_t count, uint32_t log, uint32_t *out) {
    const uint32_t grid = ((count >> log) + threads - 1) / threads;
    switch (log) {
#define STWO_FRI_LEAF_CASE(L)                                                                      \
    case L:                                                                                        \
        fri_leaf_kernel<Prefixed, L><<<grid, threads, 0, c.stream>>>(input, count, out);           \
        break
        STWO_FRI_LEAF_CASE(0);
        STWO_FRI_LEAF_CASE(1);
        STWO_FRI_LEAF_CASE(2);
        STWO_FRI_LEAF_CASE(3);
        STWO_FRI_LEAF_CASE(4);
#undef STWO_FRI_LEAF_CASE
    }
    return int(cudaPeekAtLastError());
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_fri_fold_on(void *context, uint32_t lane, const StwoRv64FriFold *p) {
    if (!p)
        return int(cudaErrorInvalidValue);
    const auto j = *p;
    if (!power2(j.count) || j.count > max_count || j.steps < 1 || j.steps > 4 ||
        j.count < (1u << j.steps) || j.first_is_circle > 1 || j.accumulate_circle > 1 ||
        (j.accumulate_circle && (!j.first_is_circle || j.steps != 1)))
        return int(cudaErrorInvalidValue);
    for (uint32_t s = 0; s < j.steps; ++s) {
        const uint64_t n = j.count >> (s + 1);
        const uint64_t need = j.first_is_circle && s == 0 ? 2 * ((n + 3) / 4) : n;
        if (j.offsets[s] > j.twiddle_words || need > j.twiddle_words - j.offsets[s])
            return int(cudaErrorInvalidValue);
    }
    Custody c(context, lane);
    if (!c.plane(j.input, j.count, 8, false) || !c.plane(j.output, j.count >> j.steps, 8, true) ||
        !c.range(j.twiddles, j.twiddle_words, false) || !c.range(j.alpha, 8, false))
        return c.status;
    const uint32_t grid = ((j.count >> j.steps) + threads - 1) / threads;
    switch (j.steps) {
#define STWO_FRI_FOLD_CASE(N)                                                                      \
    case N:                                                                                        \
        fri_fold_kernel<N><<<grid, threads, 0, c.stream>>>(j);                                     \
        break
        STWO_FRI_FOLD_CASE(1);
        STWO_FRI_FOLD_CASE(2);
        STWO_FRI_FOLD_CASE(3);
        STWO_FRI_FOLD_CASE(4);
#undef STWO_FRI_FOLD_CASE
    }
    return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_fri_leaves_on(void *context, uint32_t lane, StwoRv64Plane input,
                                       uint32_t count, uint32_t leaf_log, uint32_t prefixed,
                                       uint32_t *output, uint64_t hashes) {
    if (!power2(count) || count > max_count || leaf_log > 4 || count < (1u << leaf_log) ||
        prefixed > 1 || hashes < (count >> leaf_log) || reinterpret_cast<uintptr_t>(output) % 32)
        return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.plane(input, count, 8, false) || !c.range(output, uint64_t(count >> leaf_log) * 8, true))
        return c.status;
    return prefixed ? launch_leaves<true>(c, input, count, leaf_log, output)
                    : launch_leaves<false>(c, input, count, leaf_log, output);
}
