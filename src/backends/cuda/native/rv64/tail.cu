#include "custody.cuh"
#include "tail_math.cuh"
#include "reduce.cuh"
namespace stwo::cuda::rv64 {
constexpr uint32_t tail_capacity = 256, tail_threads = 64, tail_jobs = 8;
struct TailPacket {
    StwoRv64TailJob jobs[tail_jobs];
};
static_assert(sizeof(TailPacket) <= 4096, "bounded portable launch metadata");
// Independent transcripts map to independent blocks. Small tables never leave
// shared memory between rounds; no cooperative grid launch or global barrier.
__global__ void tail_kernel(const TailPacket packet) {
    const auto job = packet.jobs[blockIdx.x];
    __shared__ uint32_t table[16 * tail_capacity];
    __shared__ RoundState owner;
    __shared__ RoundRecord record;
    for (uint32_t i = threadIdx.x; i < round_state_words; i += tail_threads)
        reinterpret_cast<uint32_t*>(&owner)[i] = job.state[i];
    const StwoRv64Plane n{table, tail_capacity, 8, 0},
        d{table + 8 * tail_capacity, tail_capacity, 8, 0};
    for (uint32_t i = threadIdx.x; i < job.count; i += tail_threads) {
        store(
            n.words, n.stride, tail_index(i),
            job.n.coordinates == 1 ? base(job.n.words[i]) : load(job.n.words, job.n.stride, i));
        store(d.words, d.stride, tail_index(i), load(job.d.words, job.d.stride, i));
    }
    __syncthreads();
    uint32_t count = job.count;
    for (uint32_t r = job.first; r < job.variables; ++r) {
        Pair local{zero(), zero()};
        const uint32_t terms = count / 4;
        for (uint32_t i = threadIdx.x; i < terms; i += tail_threads) {
            const auto t = tail_term(n, d, count, i, job.eq, from_words(job.lambda));
            local.at0 = add(local.at0, t.at0);
            local.at2 = add(local.at2, t.at2);
        }
        const Pair raw = block_pair_sum<tail_threads>(local);
        if (!threadIdx.x)
            advance_record(&owner, job.variables, r, raw, from_words(job.point + 8 * r),
                           &record);
        __syncthreads();  // Shared challenge/state publish, including failed records.
        for (uint32_t i = threadIdx.x; i < round_record_words; i += tail_threads)
            job.records[(r - job.first) * round_record_words + i] =
                reinterpret_cast<const uint32_t*>(&record)[i];
        const auto x = record.challenge;
        const uint32_t half = count / 2;
        for (uint32_t i = threadIdx.x; i < half; i += tail_threads) {
            tail_fold_row(n, d, half, i, x);
        }
        __syncthreads();  // No reader of the next sum sees a partial fold.
        count = half;
    }
    for (uint32_t i = threadIdx.x; i < round_state_words; i += tail_threads)
        job.state[i] = reinterpret_cast<const uint32_t*>(&owner)[i];
    if (threadIdx.x < 8) {
        const uint32_t c = threadIdx.x;
        for (uint32_t i = 0; i < 2; ++i) {
            const uint32_t a = n.words[c * n.stride + i], b = d.words[c * d.stride + i];
            job.out_n.words[c * job.out_n.stride + i] = a;
            job.out_d.words[c * job.out_d.stride + i] = b;
            job.mask[8 * i + c] = a;
            job.mask[16 + 8 * i + c] = b;
        }
    }
}
}  // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_sumcheck_tail_on(void* context, uint32_t lane,
                                          const StwoRv64TailJob* jobs, uint32_t count) {
    if (!jobs || !count || count > tail_jobs) return int(cudaErrorInvalidValue);
    TailPacket packet{};
    RangeCustody<10 * tail_jobs> custody(context, lane);
    for (uint32_t i = 0; i < count; ++i) {
        const auto& j = jobs[i];
        if (!power2(j.count) || j.count < 4 || j.count > tail_capacity || j.reserved ||
            !j.variables || j.variables > 27 || j.first >= j.variables ||
            // Bounds above make the shift defined; exact equality rejects
            // a cursor whose remaining table is too large OR too small.
            j.count != (2u << (j.variables - j.first)))
            return int(cudaErrorInvalidValue);
        if (!custody.numerator(j.n, j.count) || !custody.plane(j.d, j.count, 8, false) ||
            !custody.plane(j.out_n, 2, 8, true) || !custody.plane(j.out_d, 2, 8, true) ||
            !custody.plane(j.eq, j.count / 4, 8, false) ||
            !custody.range(j.point, 8ull * j.variables, false) ||
            !custody.range(j.lambda, 8, false) ||
            !custody.range(j.state, round_state_words, true) ||
            !custody.range(j.records, (j.variables - j.first) * round_record_words, true) ||
            !custody.range(j.mask, 32, true))
            return custody.status;
        packet.jobs[i] = j;
    }
    tail_kernel<<<count, tail_threads, 0, custody.stream>>>(packet);
    return int(cudaPeekAtLastError());
}
