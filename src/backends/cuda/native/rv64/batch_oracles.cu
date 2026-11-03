#include "batch_state.cuh"
#include "custody.cuh"
#include "fold_sum.cuh"
#include "reduce.cuh"
#include <algorithm>
namespace stwo::cuda::rv64 {
struct SumPacket { StwoRv64BatchSumJob jobs[max_oracles]; };
struct FoldPacket { StwoRv64BatchFoldJob jobs[max_oracles]; };
static_assert(sizeof(SumPacket) + 256 < 32764, "bounded CUDA launch parameters");
__device__ __forceinline__ Fraction oracle_read(StwoRv64Plane n, StwoRv64Plane d,
                                                uint32_t row) {
  return {n.coordinates == 1 ? base(n.words[row]) : load(n.words, n.stride, row),
          load(d.words, d.stride, row)};
}
__device__ __forceinline__ void oracle_sum(Pair value, StwoRv64Plane output) {
  const auto sum = block_pair_sum<threads>(value);
  if (!threadIdx.x) { store(output.words, output.stride, 2 * blockIdx.x, sum.at0);
    store(output.words, output.stride, 2 * blockIdx.x + 1, sum.at2); }
}
__global__ void oracles_sum(const __grid_constant__ SumPacket packet,
                            uint32_t terms, StwoRv64Plane eq,
                            const uint32_t *lambda, bool final) {
  const auto &job = packet.jobs[blockIdx.y];
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  Pair value{zero(), zero()};
  if (i < terms) {
    const uint32_t j = 2 * i, k = 2 * (terms + i);
    const auto e = load(eq.words, eq.stride, i), l = from_words(lambda);
    if (job.n.coordinates == 1)
      value = sum_term_base(job.n.words[j], load(job.d.words, job.d.stride, j),
          job.n.words[j + 1], load(job.d.words, job.d.stride, j + 1),
          job.n.words[k], load(job.d.words, job.d.stride, k),
          job.n.words[k + 1], load(job.d.words, job.d.stride, k + 1), e, l);
    else value = sum_term(oracle_read(job.n, job.d, j), oracle_read(job.n, job.d, j + 1),
        oracle_read(job.n, job.d, k), oracle_read(job.n, job.d, k + 1), e, l);
  }
  oracle_sum(value, final ? job.out : job.a);
}
__global__ void oracles_reduce(const __grid_constant__ SumPacket packet,
                               uint32_t pairs, bool current_a, bool final) {
  const auto &job = packet.jobs[blockIdx.y];
  const auto input = current_a ? job.a : job.b;
  const auto output = final ? job.out : (current_a ? job.b : job.a);
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  Pair value{zero(), zero()};
  if (i < pairs) value = {load(input.words, input.stride, 2 * i),
                           load(input.words, input.stride, 2 * i + 1)};
  oracle_sum(value, output);
}
__global__ void oracles_fold(const __grid_constant__ FoldPacket packet,
                             uint32_t half, const uint32_t *challenge) {
  const auto &job = packet.jobs[blockIdx.y];
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < half) fold_store(job.n, job.d, half, i, from_words(challenge), job.out_n, job.out_d);
}
__global__ void oracles_layer(const __grid_constant__ FoldPacket packet,
                              uint32_t half) {
  const auto &job = packet.jobs[blockIdx.y];
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= half) return;
  const uint32_t row = 2 * i;
  const Fraction value = job.n.coordinates == 1
      ? combine_base(job.n.words[row], load(job.d.words, job.d.stride, row),
                     job.n.words[row + 1], load(job.d.words, job.d.stride, row + 1))
      : combine(oracle_read(job.n, job.d, row), oracle_read(job.n, job.d, row + 1));
  store(job.out_n.words, job.out_n.stride, i, value.n);
  store(job.out_d.words, job.out_d.stride, i, value.d);
}
inline uint32_t oracle_blocks(uint32_t count) { return (count + threads - 1) / threads; }
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_batch_sum_on(void *context, uint32_t lane,
    const StwoRv64BatchSumJob *jobs, uint32_t job_count, uint32_t count,
    StwoRv64Plane eq, const uint32_t *lambda, uint32_t *launches) {
  if (!launches) return int(cudaErrorInvalidValue); *launches = 0;
  if (!jobs || !job_count || job_count > max_oracles || !power2(count) ||
      count < 4 || count > max_count) return int(cudaErrorInvalidValue);
  const uint32_t groups = oracle_blocks(count / 4);
  RangeCustody<5 * max_oracles + 2> custody(context, lane);
  if (!custody.plane(eq, count / 4, 8, false) || !custody.range(lambda, 8, false)) return custody.status;
  for (uint32_t i = 0; i < job_count; ++i) {
    const auto &j = jobs[i];
    if (!custody.numerator(j.n, count) || !custody.plane(j.d, count, 8, false) ||
        !custody.plane(j.a, 2 * groups, 8, true) || !custody.plane(j.b, 2 * groups, 8, true) ||
        !custody.plane(j.out, 2, 8, true)) return custody.status;
  }
  SumPacket packet{}; std::copy(jobs, jobs + job_count, packet.jobs);
  oracles_sum<<<dim3(groups, job_count), threads, 0, custody.stream>>>(packet, count / 4, eq, lambda, groups == 1);
  int status = int(cudaPeekAtLastError()); if (status) return status; ++*launches;
  bool current_a = true;
  for (uint32_t pairs = groups; pairs > 1; current_a = !current_a) {
    const uint32_t blocks = oracle_blocks(pairs);
    oracles_reduce<<<dim3(blocks, job_count), threads, 0, custody.stream>>>(packet, pairs, current_a, blocks == 1);
    status = int(cudaPeekAtLastError()); if (status) return status; ++*launches; pairs = blocks;
  }
  return 0;
}
extern "C" int stwo_rv64_batch_fold_on(void *context, uint32_t lane,
    const StwoRv64BatchFoldJob *jobs, uint32_t job_count, uint32_t count,
    const uint32_t *challenge, uint32_t *launches) {
  if (!launches) return int(cudaErrorInvalidValue); *launches = 0;
  if (!jobs || !job_count || job_count > max_oracles || !power2(count) ||
      count < 2 || count > max_count) return int(cudaErrorInvalidValue);
  RangeCustody<4 * max_oracles + 1> custody(context, lane);
  if (!custody.range(challenge, 8, false)) return custody.status;
  for (uint32_t i = 0; i < job_count; ++i) {
    const auto &j = jobs[i];
    if (!custody.numerator(j.n, count) || !custody.plane(j.d, count, 8, false) ||
        !custody.plane(j.out_n, count / 2, 8, true) ||
        !custody.plane(j.out_d, count / 2, 8, true)) return custody.status;
  }
  FoldPacket packet{}; std::copy(jobs, jobs + job_count, packet.jobs);
  oracles_fold<<<dim3(oracle_blocks(count / 2), job_count), threads, 0, custody.stream>>>(packet, count / 2, challenge);
  const int status = int(cudaPeekAtLastError()); if (!status) *launches = 1; return status;
}
extern "C" int stwo_rv64_batch_layer_on(void *context, uint32_t lane,
    const StwoRv64BatchFoldJob *jobs, uint32_t job_count, uint32_t count,
    uint32_t *launches) {
  if (!launches) return int(cudaErrorInvalidValue); *launches = 0;
  if (!jobs || !job_count || job_count > max_oracles || !power2(count) ||
      count < 2 || count > max_count) return int(cudaErrorInvalidValue);
  RangeCustody<4 * max_oracles> custody(context, lane);
  for (uint32_t i = 0; i < job_count; ++i) {
    const auto &j = jobs[i];
    if (!custody.numerator(j.n, count) || !custody.plane(j.d, count, 8, false) ||
        !custody.plane(j.out_n, count / 2, 8, true) ||
        !custody.plane(j.out_d, count / 2, 8, true)) return custody.status;
  }
  FoldPacket packet{}; std::copy(jobs, jobs + job_count, packet.jobs);
  oracles_layer<<<dim3(oracle_blocks(count / 2), job_count), threads, 0, custody.stream>>>(packet, count / 2);
  const int status = int(cudaPeekAtLastError()); if (!status) *launches = 1; return status;
}
