// GPU-native native Stage 1 device kernels (M8 GPU-native, design
// rv64-m8-gpu-native.md §3.2, §3.5; native range 0x02xx of gpu_native.Check).
// Host side: src/integrations/riscv_cuda/rv64/jobs/native_device_stage1.zig.
//
// 1. stwo_rv64_n1_check_v2_on: one acceptance check = exactly one Verdict word.
//    Inputs are up to 8 "must be zero" words (device status/verdict words of
//    the producers: GKR closure status, binding verdict, witness status), up
//    to 4 equal-pairs (a[0..words) == b[0..words): FIXED device root vs the
//    class authority root, the exchanged MAIN root vs the GKR-bound root) and
//    up to 4 constant runs (a[0..words) == values[0..words), values carried in
//    the launch parameters: the plan-determined guard words of a device
//    channel snapshot or traversal header - cursor, chain, status latch,
//    draws, layer/phase counters - i.e. the legacy host Snapshot.validate /
//    Header.validate, so no expected value needs device memory). Accept (0)
//    iff every zero word is 0, every pair is equal and every run matches;
//    otherwise (check << 16) | detail, detail = 1 + index of the first failing
//    input (zero words first, then pairs at 0x10 + index, then constant runs
//    at 0x20 + index). A zero word holding Verdict.unset (0xffffffff: its
//    producer never ran) also rejects. One thread: a few dozen words.
//    v2 = v1 + constant runs (the v1 symbol is gone: its ABI was smaller).
//
// 2. stwo_rv64_n1_scatter_v1_on: chunked MAIN evaluation ingress. Copies a
//    run table {dst offset, src offset, words} from a staged chunk buffer into
//    the segment's MAIN evaluation image (grid-stride, one launch per chunk;
//    the run table and the data are device memory). Run bounds are validated
//    against both buffers on device: an out-of-range run writes no word and
//    ORs witness detail 1 into `status` (Check.witness_status reads it).
//
// Enqueue only, no sync, no readback.
#include "rv64/custody.cuh"
#include <stdint.h>

struct StwoRv64N1Pair {
  const uint32_t *a;
  const uint32_t *b;
  uint32_t words;
  uint32_t reserved;
};
struct StwoRv64N1Const {
  const uint32_t *a;
  uint32_t words;  // 1..16
  uint32_t reserved;
  uint32_t values[16];
};
struct StwoRv64N1Check {
  const uint32_t *zero[8];
  StwoRv64N1Pair pairs[4];
  StwoRv64N1Const consts[4];
  uint32_t n_zero;
  uint32_t n_pairs;
  uint32_t n_consts;
  uint32_t check;  // gpu_native.Check id (0x02xx)
};
static_assert(sizeof(StwoRv64N1Pair) == 24, "n1 pair ABI");
static_assert(sizeof(StwoRv64N1Const) == 80, "n1 const ABI");
static_assert(sizeof(StwoRv64N1Check) == 8 * 8 + 4 * 24 + 4 * 80 + 16, "n1 check ABI");

struct StwoRv64N1Run {
  uint64_t dst;    // word offset in the MAIN evaluation image
  uint64_t src;    // word offset in the chunk buffer
  uint64_t words;  // run length
};
static_assert(sizeof(StwoRv64N1Run) == 24, "n1 run ABI");

namespace stwo::cuda::rv64 {
namespace {
__global__ void n1_check(StwoRv64N1Check c, uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  for (uint32_t i = 0; i < c.n_zero && !detail; ++i)
    if (c.zero[i][0] != 0u) detail = 1 + i;
  for (uint32_t p = 0; p < c.n_pairs && !detail; ++p)
    for (uint32_t k = 0; k < c.pairs[p].words; ++k)
      if (c.pairs[p].a[k] != c.pairs[p].b[k]) {
        detail = 0x10 + p;
        break;
      }
  for (uint32_t q = 0; q < c.n_consts && !detail; ++q)
    for (uint32_t k = 0; k < c.consts[q].words; ++k)
      if (c.consts[q].a[k] != c.consts[q].values[k]) {
        detail = 0x20 + q;
        break;
      }
  verdict[0] = detail ? ((c.check << 16) | detail) : 0u;
}

__global__ void n1_scatter(const StwoRv64N1Run *runs, uint32_t n_runs, const uint32_t *chunk,
                           uint64_t chunk_words, uint32_t *image, uint64_t image_words,
                           uint32_t *status) {
  for (uint32_t r = 0; r < n_runs; ++r) {
    const StwoRv64N1Run run = runs[r];
    const bool ok = run.words <= chunk_words && run.src <= chunk_words - run.words &&
                    run.words <= image_words && run.dst <= image_words - run.words;
    if (!ok) {
      if (blockIdx.x == 0 && threadIdx.x == 0) atomicOr(status, 1u);
      continue;
    }
    for (uint64_t i = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x; i < run.words;
         i += uint64_t(gridDim.x) * blockDim.x)
      image[run.dst + i] = chunk[run.src + i];
  }
}
}  // namespace
}  // namespace stwo::cuda::rv64

// Every pointer is device memory of `context`; verdict: 1 word (written).
extern "C" int stwo_rv64_n1_check_v2_on(void *context, uint32_t lane, const StwoRv64N1Check *check,
                                        uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!check || check->n_zero > 8 || check->n_pairs > 4 || check->n_consts > 4 || (check->check >> 8) != 0x02u)
    return int(cudaErrorInvalidValue);
  for (uint32_t q = 0; q < check->n_consts; ++q)
    if (!check->consts[q].a || !check->consts[q].words || check->consts[q].words > 16)
      return int(cudaErrorInvalidValue);
  for (uint32_t p = 0; p < check->n_pairs; ++p)
    if (!check->pairs[p].a || !check->pairs[p].b || !check->pairs[p].words || check->pairs[p].words > 4096)
      return int(cudaErrorInvalidValue);
  for (uint32_t i = 0; i < check->n_zero; ++i)
    if (!check->zero[i]) return int(cudaErrorInvalidValue);
  RangeCustody<1> custody(context, lane);
  if (!custody.range(verdict, 1, true)) return custody.status;
  n1_check<<<1, 1, 0, custody.stream>>>(*check, verdict);
  return int(cudaPeekAtLastError());
}

// runs: n_runs records (device); chunk: chunk_words; image: image_words;
// status: 1 word (OR-ed, caller clears it first).
extern "C" int stwo_rv64_n1_scatter_v1_on(void *context, uint32_t lane, const StwoRv64N1Run *runs,
                                          uint32_t n_runs, const uint32_t *chunk, uint64_t chunk_words,
                                          uint32_t *image, uint64_t image_words, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!runs || !n_runs || !chunk || !chunk_words || !image || !image_words || !status)
    return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(reinterpret_cast<const uint32_t *>(runs), uint64_t(n_runs) * 6, false) ||
      !custody.range(chunk, chunk_words, false) || !custody.range(image, image_words, true) ||
      !custody.range(status, 1, true))
    return custody.status;
  // 2 x 170 SMs x 256 threads covers a 2^20-word run in ~12 strides; the
  // copy is bandwidth bound either way. [E] (not tuned: no A/B measured).
  const uint32_t blocks = 340;
  n1_scatter<<<blocks, 256, 0, custody.stream>>>(runs, n_runs, chunk, chunk_words, image, image_words, status);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_n1_version(void) {
  return 2;
}
