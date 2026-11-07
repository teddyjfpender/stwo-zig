// Mixed-height native LogUp sumcheck: one polynomial and challenge per round.
#include "batch_transition.cuh"
#include "fold_sum.cuh"
#include "reduce.cuh"
#include "custody.cuh"
#include "round.cuh"
#include <algorithm>
#include <cstdlib>
#include <cstring>
namespace stwo::cuda::rv64 {
// STWO_RV64_M8_GKR_BATCH_PAR (default off; read once per process): 1 runs the
// mixed-oracle round transition on one CTA (advance_batch_round_block) for both
// batch_round and batch_tail; 0/unset keeps the serial <<<1,1>>> transition.
// Any other value rejects. Records, state and status words are bit-identical.
inline int batch_par_mode() {
  static const int mode = [] {
    const char *v = std::getenv("STWO_RV64_M8_GKR_BATCH_PAR");
    if (!v || !std::strcmp(v, "0")) return 0;
    if (!std::strcmp(v, "1")) return 1;
    return -1;
  }();
  return mode;
}
// One thread per oracle slot (max_oracles = 128) plus the helper warp
// (advance_batch_round_block).
constexpr uint32_t batch_par_oracle_threads = max_oracles,
                   batch_par_threads = batch_par_oracle_threads + 32;
__global__ void batch_init(uint32_t *words, const uint32_t *seed,
                           const uint32_t *claims, const uint32_t *alpha_words,
                           BatchJobs jobs) {
  auto *s = reinterpret_cast<BatchState *>(words);
  const OM31 alpha = from_words(alpha_words);
  bool valid = canonical(alpha);
  for (uint32_t i = 0; i < jobs.count; ++i)
    valid = valid && canonical(from_words(claims + 8 * i));
  for (uint32_t i = 0; i < 9; ++i)
    s->initial_seed[i] = seed[i];
  s->initial_alpha = alpha;
  OM31 total = zero(), weight = one();
  for (uint32_t i = 0; i < max_oracles; ++i) {
    s->initial_claims[i] =
        valid && i < jobs.count ? from_words(claims + 8 * i) : zero();
    s->initial_variables[i] = i < jobs.count ? jobs.oracles[i].variables : 0;
    s->weights[i] = s->sleeping_claims[i] = zero();
    s->corrections[i] = one();
    if (valid && i < jobs.count) {
      s->weights[i] = weight;
      s->sleeping_claims[i] =
          scale(mul(weight, from_words(claims + 8 * i)),
                1u << (jobs.variables - jobs.oracles[i].variables));
      total = add(total, s->sleeping_claims[i]);
      weight = mul(weight, alpha);
    }
  }
  initialize_round(&s->round, seed, total, jobs.variables);
  if (!valid)
    s->round.status = round_field;
  if (seed[8] > (1u << 20))
    s->round.status = round_order;
  s->count = jobs.count;
  for (auto &v : s->reserved)
    v = 0;
}
__global__ void batch_round(uint32_t *words, BatchJobs jobs, uint32_t expected,
                            const uint32_t *point, uint32_t *record_words) {
  advance_batch_round(reinterpret_cast<BatchState *>(words), jobs, expected,
                      point, reinterpret_cast<RoundRecord *>(record_words));
}
__global__ void __launch_bounds__(batch_par_threads)
batch_round_par(uint32_t *words, const __grid_constant__ BatchJobs jobs, uint32_t expected,
                const uint32_t *point, uint32_t *record_words) {
  advance_batch_round_block<batch_par_oracle_threads, batch_par_threads>(
      reinterpret_cast<BatchState *>(words), jobs, expected, point,
      reinterpret_cast<RoundRecord *>(record_words));
}
__device__ __forceinline__ void write_batch_mask(StwoRv64Plane n, StwoRv64Plane d, uint32_t *output) {
  const uint32_t c = threadIdx.x;
  if (c >= 8)
    return;
  for (uint32_t row = 0; row < 2; ++row) {
    output[8 * row + c] = n.coordinates == 1 ? (c == 0 ? n.words[row] : 0)
                                             : n.words[c * n.stride + row];
    output[16 + 8 * row + c] = d.words[c * d.stride + row];
  }
}
__global__ void batch_mask(StwoRv64Plane n, StwoRv64Plane d, uint32_t *output) {
  write_batch_mask(n, d, output);
}
struct MaskPacket { StwoRv64BatchMaskJob jobs[max_oracles]; };
__global__ void batch_masks(const __grid_constant__ MaskPacket packet) {
  const auto &job = packet.jobs[blockIdx.x];
  write_batch_mask(job.n, job.d, job.output);
}
using BatchCustody = RangeCustody<max_oracles + 8>;
inline int jobs_for(BatchCustody &c, const StwoRv64BatchOracle *oracles,
                    uint32_t count, uint32_t variables, BatchJobs *jobs) {
  if (!oracles || !count || count > max_oracles || variables > 27)
    return int(cudaErrorInvalidValue);
  uint32_t largest = 0;
  *jobs = {};
  for (uint32_t i = 0; i < count; ++i) {
    const auto job = oracles[i];
    if (job.reserved || job.variables > variables)
      return int(cudaErrorInvalidValue);
    largest = largest > job.variables ? largest : job.variables;
    if (job.variables == 0) {
      if (job.raw || job.raw_stride)
        return int(cudaErrorInvalidValue);
    } else {
      if (job.raw_stride < 2 || job.raw_stride > UINT64_MAX / 8)
        return int(cudaErrorInvalidValue);
      if (!c.range(job.raw, 8 * job.raw_stride, false))
        return c.status;
    }
    jobs->oracles[i] = job;
  }
  if (largest != variables)
    return int(cudaErrorInvalidValue);
  jobs->count = count;
  jobs->variables = variables;
  return 0;
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_batch_init_on(void *ctx, uint32_t lane,
                                       uint32_t *state, const uint32_t *seed,
                                       const uint32_t *claims,
                                       const uint32_t *alpha,
                                       const StwoRv64BatchOracle *oracles,
                                       uint32_t count, uint32_t variables) {
  BatchCustody c(ctx, lane);
  BatchJobs jobs;
  if (const int status = jobs_for(c, oracles, count, variables, &jobs))
    return status;
  if (!c.range(state, STWO_RV64_BATCH_STATE_WORDS, true) ||
      !c.range(seed, 9, false) || !c.range(claims, 8ull * count, false) ||
      !c.range(alpha, 8, false))
    return c.status;
  batch_init<<<1, 1, 0, c.stream>>>(state, seed, claims, alpha, jobs);
  return int(cudaPeekAtLastError());
}
extern "C" int
stwo_rv64_batch_round_on(void *ctx, uint32_t lane, uint32_t *state,
                         const StwoRv64BatchOracle *oracles, uint32_t count,
                         uint32_t variables, uint32_t expected,
                         const uint32_t *point, uint32_t *record) {
  if (!variables || expected >= variables)
    return int(cudaErrorInvalidValue);
  const int par = batch_par_mode();
  if (par < 0)
    return int(cudaErrorInvalidValue);
  BatchCustody c(ctx, lane);
  BatchJobs jobs;
  if (const int status = jobs_for(c, oracles, count, variables, &jobs))
    return status;
  if (!c.range(state, STWO_RV64_BATCH_STATE_WORDS, true) ||
      !c.range(point, 8ull * variables, false) ||
      !c.range(record, round_record_words, true))
    return c.status;
  if (par)
    batch_round_par<<<1, batch_par_threads, 0, c.stream>>>(state, jobs, expected, point, record);
  else
    batch_round<<<1, 1, 0, c.stream>>>(state, jobs, expected, point, record);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_batch_mask_on(void *ctx, uint32_t lane,
                                       StwoRv64Plane n, StwoRv64Plane d,
                                       uint32_t *output) {
  Custody c(ctx, lane);
  if (!c.numerator(n, 2) || !c.plane(d, 2, 8, false) ||
      !c.range(output, 32, true))
    return c.status;
  batch_mask<<<1, 32, 0, c.stream>>>(n, d, output);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_batch_masks_on(void *ctx, uint32_t lane,
    const StwoRv64BatchMaskJob *jobs, uint32_t count) {
  if (!jobs || !count || count > max_oracles) return int(cudaErrorInvalidValue);
  RangeCustody<3 * max_oracles> c(ctx, lane);
  for (uint32_t i = 0; i < count; ++i) {
    if (!c.numerator(jobs[i].n, 2) || !c.plane(jobs[i].d, 2, 8, false) ||
        !c.range(jobs[i].output, 32, true)) return c.status;
  }
  MaskPacket packet{};
  std::copy(jobs, jobs + count, packet.jobs);
  batch_masks<<<count, 32, 0, c.stream>>>(packet);
  return int(cudaPeekAtLastError());
}

namespace stwo::cuda::rv64 {
constexpr uint32_t batch_tail_threads = 256, batch_tail_rounds = 4;
struct BatchTailPacket {
  StwoRv64BatchTailOracle oracles[max_oracles];
  uint32_t count, variables, first, reserved;
  uint32_t *state;
  const uint32_t *point;
  StwoRv64Plane eq;
  const uint32_t *lambda;
  uint32_t *records;
};
// 128 oracles: above the legacy 4 KiB parameter limit; CUDA 12.1+ on sm_70+ admits 32,764 bytes (batch_oracles.cu
// SumPacket already relies on it at 64 oracles).
static_assert(sizeof(BatchTailPacket) <= 32764, "bounded tail launch");
struct TailCursor { StwoRv64Plane n, d, out_n, out_d; uint32_t count; };
template <bool Par>
__global__ void batch_tail(const __grid_constant__ BatchTailPacket packet) {
  __shared__ BatchState owner;
  __shared__ BatchJobs jobs;
  __shared__ TailCursor cursors[max_oracles];
  __shared__ uint32_t raw[max_oracles][16];
  __shared__ RoundRecord record;
  for (uint32_t i = threadIdx.x; i < STWO_RV64_BATCH_STATE_WORDS; i += blockDim.x)
    reinterpret_cast<uint32_t *>(&owner)[i] = packet.state[i];
  for (uint32_t j = threadIdx.x; j < packet.count; j += blockDim.x) {
    const auto o = packet.oracles[j];
    cursors[j] = {{const_cast<uint32_t *>(o.n), o.input_stride, o.numerator_coordinates, 0},
                  {const_cast<uint32_t *>(o.d), o.input_stride, 8, 0},
                  {o.out_n, o.output_stride, 8, 0}, {o.out_d, o.output_stride, 8, 0},
                  2u << min(o.variables, packet.variables - packet.first)};
    jobs.oracles[j] = {o.variables ? raw[j] : nullptr, o.variables ? 2ull : 0ull, o.variables, 0};
  }
  if (!threadIdx.x) { jobs.count = packet.count; jobs.variables = packet.variables; }
  __syncthreads();
  const uint32_t lane = threadIdx.x & 31u, warp = threadIdx.x >> 5;
  for (uint32_t r = packet.first; r < packet.variables; ++r) {
    const uint32_t remaining = packet.variables - r;
    for (uint32_t j = warp; j < packet.count; j += batch_tail_threads / 32) {
      if (packet.oracles[j].variables < remaining) continue;
      const auto c = cursors[j]; const uint32_t terms = c.count / 4;
      Pair value{zero(), zero()};
      for (uint32_t i = lane; i < terms; i += 32) {
        const uint32_t a = 2 * i, b = 2 * (terms + i);
        const auto e = load(packet.eq.words, packet.eq.stride, i), l = from_words(packet.lambda);
        Pair term;
        if (c.n.coordinates == 1)
          term = sum_term_base(c.n.words[a], load(c.d.words,c.d.stride,a),
              c.n.words[a+1],load(c.d.words,c.d.stride,a+1), c.n.words[b],load(c.d.words,c.d.stride,b),
              c.n.words[b+1],load(c.d.words,c.d.stride,b+1),e,l);
        else
          term = sum_term({load(c.n.words,c.n.stride,a),load(c.d.words,c.d.stride,a)},
              {load(c.n.words,c.n.stride,a+1),load(c.d.words,c.d.stride,a+1)},
              {load(c.n.words,c.n.stride,b),load(c.d.words,c.d.stride,b)},
              {load(c.n.words,c.n.stride,b+1),load(c.d.words,c.d.stride,b+1)},e,l);
        value.at0=add(value.at0,term.at0); value.at2=add(value.at2,term.at2);
      }
      value.at0=warp_sum(value.at0); value.at2=warp_sum(value.at2);
      if (!lane) for (uint32_t k=0;k<8;++k) {
        raw[j][2*k]=coordinate(value.at0,k); raw[j][2*k+1]=coordinate(value.at2,k);
      }
    }
    __syncthreads();
    if constexpr (Par) advance_batch_round_block<max_oracles,batch_tail_threads>(&owner,jobs,r,packet.point,&record);
    else if (!threadIdx.x) advance_batch_round(&owner,jobs,r,packet.point,&record);
    __syncthreads();
    for (uint32_t i=threadIdx.x;i<round_record_words;i+=blockDim.x)
      packet.records[(r-packet.first)*round_record_words+i]=reinterpret_cast<const uint32_t *>(&record)[i];
    for (uint32_t j=warp;j<packet.count;j+=batch_tail_threads/32) {
      if (packet.oracles[j].variables < remaining) continue;
      const auto c=cursors[j]; const uint32_t half=c.count/2;
      for (uint32_t i=lane;i<half;i+=32) fold_store(c.n,c.d,half,i,record.challenge,c.out_n,c.out_d);
      __syncwarp();
      if (!lane) { cursors[j].n=c.out_n; cursors[j].d=c.out_d; cursors[j].count=half; }
    }
    // All readers in the next round observe the completed in-place folds.
    __syncthreads();
  }
  for (uint32_t i=threadIdx.x;i<STWO_RV64_BATCH_STATE_WORDS;i+=blockDim.x)
    packet.state[i]=reinterpret_cast<const uint32_t *>(&owner)[i];
  for (uint32_t i=threadIdx.x;i<packet.count*8;i+=blockDim.x) {
    const uint32_t j=i/8,k=i%8; const auto c=cursors[j];
    for (uint32_t row=0;row<2;++row) {
      packet.oracles[j].mask[8*row+k]=c.n.coordinates==1?(k?0:c.n.words[row]):c.n.words[k*c.n.stride+row];
      packet.oracles[j].mask[16+8*row+k]=c.d.words[k*c.d.stride+row];
    }
  }
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_batch_tail_on(void *context,uint32_t lane,uint32_t *state,
    const StwoRv64BatchTailOracle *oracles,uint32_t count,uint32_t variables,uint32_t first,
    const uint32_t *point,StwoRv64Plane eq,const uint32_t *lambda,uint32_t *records) {
  using namespace stwo::cuda::rv64;
  const int par=batch_par_mode();
  if (par<0) return int(cudaErrorInvalidValue);
  if (!oracles||!count||count>max_oracles||!variables||variables>27||first>=variables||variables-first>batch_tail_rounds)
    return int(cudaErrorInvalidValue);
  BatchTailPacket packet{};packet.count=count;packet.variables=variables;packet.first=first;
  packet.state=state;packet.point=point;packet.eq=eq;packet.lambda=lambda;packet.records=records;
  RangeCustody<5*max_oracles+5> c(context,lane);
  if (!c.range(state,STWO_RV64_BATCH_STATE_WORDS,true)||!c.range(point,8ull*variables,false)||
      !c.range(lambda,8,false)||!c.plane(eq,1u<<(variables-first-1),8,false)||
      !c.range(records,uint64_t(variables-first)*round_record_words,true)) return c.status;
  for (uint32_t j=0;j<count;++j) {
    const auto &o=oracles[j]; if(o.variables>variables||(o.numerator_coordinates!=1&&o.numerator_coordinates!=8))return int(cudaErrorInvalidValue);
    const uint32_t n=2u<<std::min(o.variables,variables-first);
    StwoRv64Plane pn{const_cast<uint32_t *>(o.n),o.input_stride,o.numerator_coordinates,0},pd{const_cast<uint32_t *>(o.d),o.input_stride,8,0};
    if(!c.numerator(pn,n)||!c.plane(pd,n,8,false)||!c.range(o.mask,32,true))return c.status;
    if(o.variables) {
      StwoRv64Plane on{o.out_n,o.output_stride,8,0},od{o.out_d,o.output_stride,8,0};
      if(!c.plane(on,n/2,8,true)||!c.plane(od,n/2,8,true))return c.status;
    } else if(o.out_n||o.out_d||o.output_stride) return int(cudaErrorInvalidValue);
    packet.oracles[j]=o;
  }
  if (par) batch_tail<true><<<1,batch_tail_threads,0,c.stream>>>(packet);
  else batch_tail<false><<<1,batch_tail_threads,0,c.stream>>>(packet);
  return int(cudaPeekAtLastError());
}
