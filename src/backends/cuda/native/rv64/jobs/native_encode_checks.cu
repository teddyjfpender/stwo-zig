// Native Stage-2 acceptance checks on device (M8 GPU-native, design
// rv64-m8-gpu-native.md §3.5; native range of gpu_native.Check; piece
// n-stage2). Each check is one enqueued kernel that writes exactly one
// gpu_native.Verdict word (0 accepted, (check << 16) | detail rejected) into
// the request slab. Enqueue only, no sync, no readback. Host references:
//
//   root_match        native_pcs.checkRoots (PCS-rebuilt roots == committed
//                     roots) + PendingManifest.checkPhysicalRoots (FIXED ==
//                     the class FIXED authority; MAIN == the stage-one root)
//   global_status /   `for (job.global_status) |st| if (st != 0)` and
//   composition_accept native_stage2.accept: every status word is zero
//   public_claims     cpu_worker.publicClaims: canonical claims and, for the
//                     core initial / terminal RAM slots, claim ==
//                     expected_boundary.claim(cells, initial, shared.ram):
//                     sign * sum_c 1 / (offset - sum_k coeff_k * tuple_c[k])
//
// Plus the parameter patch used by the Stage-2 job: out[dst[i] .. +8] =
// src[8 * index[i] .. +8] (global projection parameters from the device-drawn
// shared challenges; no host value of a challenge exists on this path).
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

namespace stwo::cuda::rv64::native_checks {
namespace {
constexpr uint32_t kRootMatch = 0x0208u, kPublicClaims = 0x0206u;
constexpr uint32_t kThreads = 256;
__device__ __forceinline__ uint32_t verdict(uint32_t check, uint32_t detail) {
  return detail ? ((check << 16) | (detail & 0xffffu ? detail & 0xffffu : 1u)) : 0u;
}

struct RootArgs {
  const uint32_t *expected[4];
  uint32_t trees;
  uint32_t fixed[8];  // class FIXED authority (tree 0)
  uint32_t check_fixed;
};

// detail 1 = header tree count, 0x10 + t = tree t rebuilt root != committed,
// 2 = committed FIXED root != class authority.
__global__ void root_match(const uint32_t *pcs, RootArgs args, uint32_t *out) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  if (pcs[7] != args.trees) detail = 1;
  for (uint32_t t = 0; t < args.trees && !detail; ++t)
    for (uint32_t i = 0; i < 8; ++i)
      if (pcs[31 + 8 * t + i] != args.expected[t][i]) detail = 0x10 + t;
  if (!detail && args.check_fixed)
    for (uint32_t i = 0; i < 8; ++i)
      if (args.expected[0][i] != args.fixed[i]) detail = 2;
  *out = verdict(kRootMatch, detail);
}

// detail = 1 + index of the first nonzero word (saturated at 0xffff).
__global__ void words_zero(const uint32_t *words, uint32_t count, uint32_t check, uint32_t *out) {
  __shared__ uint32_t first;
  if (threadIdx.x == 0) first = UINT32_MAX;
  __syncthreads();
  for (uint32_t i = threadIdx.x; i < count; i += blockDim.x)
    if (words[i] != 0) atomicMin(&first, i);
  __syncthreads();
  if (threadIdx.x == 0) *out = first == UINT32_MAX ? 0u : ((check << 16) | (first + 1 > 0xffffu ? 0xffffu : first + 1));
}

// One boundary relation (initial or terminal RAM) of public_claims.
struct BoundaryArgs {
  uint32_t claim;       // claim index in the Stage-2 claims buffer
  uint32_t cells;       // rows of `tuples` (14 canonical M31 words each)
  uint32_t initial;     // 1: subtract the inverses, 0: add them
  uint32_t reserved;
};
constexpr uint32_t kTupleWords = 14;
enum PublicDetail : uint32_t { kNoncanonicalClaim = 1, kNoncanonicalChallenge = 2, kZeroDenominator = 3, kMismatch = 4, kNoncanonicalTuple = 5 };

// partial[b] = sum over this block's cells of 1 / d(c); flags in status.
__global__ void boundary_partials(const uint32_t *tuples, uint32_t cells, const uint32_t *ram, OM31 *partials,
                                  uint32_t *status) {
  __shared__ OM31 acc[kThreads];
  OM31 sum = zero();
  const OM31 offset = from_words(ram);
  for (uint32_t c = blockIdx.x * blockDim.x + threadIdx.x; c < cells; c += gridDim.x * blockDim.x) {
    OM31 d = offset;
    for (uint32_t k = 0; k < kTupleWords; ++k) {
      const uint32_t v = tuples[uint64_t(c) * kTupleWords + k];
      if (v >= q::kPrime) atomicCAS(status, 0u, kNoncanonicalTuple);
      d = sub(d, scale(from_words(ram + 8 * (1 + k)), v));
    }
    if (is_zero(d)) atomicCAS(status, 0u, kZeroDenominator);
    else sum = add(sum, inverse_nonzero(d));
  }
  acc[threadIdx.x] = sum;
  __syncthreads();
  for (uint32_t s = blockDim.x / 2; s; s >>= 1) {
    if (threadIdx.x < s) acc[threadIdx.x] = add(acc[threadIdx.x], acc[threadIdx.x + s]);
    __syncthreads();
  }
  if (threadIdx.x == 0) partials[blockIdx.x] = acc[0];
}

__global__ void public_claims_finish(const uint32_t *claims, uint32_t claim_count, const uint32_t *ram,
                                     const OM31 *partials, uint32_t blocks_initial, uint32_t blocks_terminal,
                                     BoundaryArgs initial, BoundaryArgs terminal, uint32_t *status, uint32_t *out) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = *status;
  for (uint32_t i = 0; i < claim_count * 8 && !detail; ++i)
    if (claims[i] >= q::kPrime) detail = kNoncanonicalClaim;
  for (uint32_t i = 0; i < 15 * 8 && !detail; ++i)
    if (ram[i] >= q::kPrime) detail = kNoncanonicalChallenge;
  const BoundaryArgs rel[2] = {initial, terminal};
  const uint32_t blocks[2] = {blocks_initial, blocks_terminal};
  uint32_t first = 0;
  for (uint32_t r = 0; r < 2 && !detail; ++r) {
    if (rel[r].claim == UINT32_MAX) continue;
    OM31 sum = zero();
    for (uint32_t b = 0; b < blocks[r]; ++b) sum = add(sum, partials[first + b]);
    first += blocks[r];
    const OM31 expected = rel[r].initial ? sub(zero(), sum) : sum;
    const OM31 claim = from_words(claims + 8 * uint64_t(rel[r].claim));
    for (uint32_t c = 0; c < 8; ++c)
      if (coordinate(claim, c) != coordinate(expected, c)) detail = kMismatch;
  }
  *out = verdict(kPublicClaims, detail);
}

// Out-of-range table entries are skipped (the host builder validates the
// tables against the plan; this guard only keeps a bad table in bounds).
__global__ void patch_words(const uint32_t *src, uint32_t src_felts, const uint32_t *index, const uint32_t *dst,
                            uint32_t count, uint32_t *out, uint64_t out_words) {
  for (uint32_t k = blockIdx.x * blockDim.x + threadIdx.x; k < 8 * count; k += gridDim.x * blockDim.x) {
    const uint64_t at = uint64_t(dst[k / 8]) + (k % 8);
    const uint32_t from = index[k / 8];
    if (at < out_words && from < src_felts) out[at] = src[8 * uint64_t(from) + (k % 8)];
  }
}
}  // namespace
}  // namespace stwo::cuda::rv64::native_checks

using stwo::cuda::rv64::RangeCustody;
namespace nc = stwo::cuda::rv64::native_checks;

struct StwoRv64NativeRootMatch {
  const uint32_t *expected[4];  // 8 committed root words per tree (device)
  uint32_t trees;
  uint32_t fixed[8];
  uint32_t check_fixed;
};
static_assert(sizeof(StwoRv64NativeRootMatch) == 72, "root match ABI");

extern "C" int stwo_rv64_native_root_match_v1_on(void *context, uint32_t lane, const uint32_t *pcs, uint64_t pcs_words,
                                                const StwoRv64NativeRootMatch *args, uint32_t *verdict) {
  if (!args || args->trees == 0 || args->trees > 4 || pcs_words < 31 + 8ull * args->trees) return int(cudaErrorInvalidValue);
  RangeCustody<6> custody(context, lane);
  if (!custody.range(pcs, 31 + 8ull * args->trees, false) || !custody.range(verdict, 1, true)) return custody.status;
  for (uint32_t t = 0; t < args->trees; ++t)
    if (!custody.range(args->expected[t], 8, false)) return custody.status;
  nc::RootArgs a{};
  for (uint32_t t = 0; t < 4; ++t) a.expected[t] = t < args->trees ? args->expected[t] : nullptr;
  a.trees = args->trees;
  for (uint32_t i = 0; i < 8; ++i) a.fixed[i] = args->fixed[i];
  a.check_fixed = args->check_fixed;
  nc::root_match<<<1, 1, 0, custody.stream>>>(pcs, a, verdict);
  return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_native_words_zero_check_v1_on(void *context, uint32_t lane, const uint32_t *words,
                                                      uint32_t count, uint32_t check, uint32_t *verdict) {
  if (!count || check == 0 || check > 0xffffu) return int(cudaErrorInvalidValue);
  RangeCustody<2> custody(context, lane);
  if (!custody.range(words, count, false) || !custody.range(verdict, 1, true)) return custody.status;
  nc::words_zero<<<1, 256, 0, custody.stream>>>(words, count, check, verdict);
  return int(cudaPeekAtLastError());
}

struct StwoRv64NativeBoundary {
  uint32_t claim;  // UINT32_MAX: relation absent
  uint32_t cells;
  uint32_t initial;
  uint32_t reserved;
};
static_assert(sizeof(StwoRv64NativeBoundary) == 16, "boundary ABI");

// Scratch words for `stwo_rv64_native_public_claims_check_v1_on`: one status
// word + 8 words per reduction block (blocks = min(256, ceil(cells / 256))).
extern "C" uint64_t stwo_rv64_native_public_claims_scratch_words_v1(uint32_t initial_cells, uint32_t terminal_cells) {
  auto blocks = [](uint32_t cells) -> uint64_t { return cells ? (cells + 255u) / 256u < 256u ? (cells + 255u) / 256u : 256u : 0u; };
  return 8 + 8 * (blocks(initial_cells) + blocks(terminal_cells));
}

// claims: claim_count x 8 words (Stage-2 claims buffer); ram: 15 x 8 words
// (shared RAM challenges: offset, 14 coefficients; drawn on device by the
// seal); tuples_*: cells x 14 canonical words (boundary rows, request input).
extern "C" int stwo_rv64_native_public_claims_check_v1_on(void *context, uint32_t lane, const uint32_t *claims,
                                                         uint32_t claim_count, const uint32_t *ram,
                                                         const uint32_t *tuples_initial,
                                                         const StwoRv64NativeBoundary *initial,
                                                         const uint32_t *tuples_terminal,
                                                         const StwoRv64NativeBoundary *terminal, uint32_t *scratch,
                                                         uint64_t scratch_words, uint32_t *verdict) {
  if (!initial || !terminal || !claim_count) return int(cudaErrorInvalidValue);
  const StwoRv64NativeBoundary *rel[2] = {initial, terminal};
  const uint32_t *tuples[2] = {tuples_initial, tuples_terminal};
  for (uint32_t r = 0; r < 2; ++r)
    if (rel[r]->claim != UINT32_MAX && (rel[r]->claim >= claim_count)) return int(cudaErrorInvalidValue);
  const uint32_t ci = initial->claim == UINT32_MAX ? 0 : initial->cells, ct = terminal->claim == UINT32_MAX ? 0 : terminal->cells;
  if (scratch_words < stwo_rv64_native_public_claims_scratch_words_v1(ci, ct)) return int(cudaErrorInvalidValue);
  RangeCustody<6> custody(context, lane);
  if (!custody.range(claims, uint64_t(claim_count) * 8, false) || !custody.range(ram, 15 * 8, false) ||
      !custody.range(scratch, scratch_words, true) || !custody.range(verdict, 1, true))
    return custody.status;
  for (uint32_t r = 0; r < 2; ++r)
    if (rel[r]->claim != UINT32_MAX && rel[r]->cells && !custody.range(tuples[r], uint64_t(rel[r]->cells) * nc::kTupleWords, false))
      return custody.status;
  uint32_t *status = scratch;
  auto *partials = reinterpret_cast<stwo::cuda::rv64::OM31 *>(scratch + 8);
  cudaMemsetAsync(status, 0, 4, custody.stream);
  uint32_t blocks[2] = {0, 0}, first = 0;
  const uint32_t cells[2] = {ci, ct};
  for (uint32_t r = 0; r < 2; ++r) {
    if (!cells[r]) continue;
    blocks[r] = (cells[r] + 255u) / 256u < 256u ? (cells[r] + 255u) / 256u : 256u;
    nc::boundary_partials<<<blocks[r], nc::kThreads, 0, custody.stream>>>(tuples[r], cells[r], ram, partials + first, status);
    first += blocks[r];
  }
  const nc::BoundaryArgs a{initial->claim, ci, initial->initial, 0}, b{terminal->claim, ct, terminal->initial, 0};
  nc::public_claims_finish<<<1, 1, 0, custody.stream>>>(claims, claim_count, ram, partials, blocks[0], blocks[1], a, b,
                                                         status, verdict);
  return int(cudaPeekAtLastError());
}

// out[dst[i] + c] = src[8 * index[i] + c], c < 8, i < count. dst/index:
// device tables (class constants); src: src_felts x 8 words.
extern "C" int stwo_rv64_native_patch_felts_v1_on(void *context, uint32_t lane, const uint32_t *src, uint32_t src_felts,
                                                 const uint32_t *index, const uint32_t *dst, uint32_t count,
                                                 uint32_t *out, uint64_t out_words) {
  if (!count || !src_felts) return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(src, uint64_t(src_felts) * 8, false) || !custody.range(index, count, false) ||
      !custody.range(dst, count, false) || !custody.range(out, out_words, true))
    return custody.status;
  const uint32_t blocks = (8 * count + 255) / 256 < 64 ? (8 * count + 255) / 256 : 64;
  nc::patch_words<<<blocks, 256, 0, custody.stream>>>(src, src_felts, index, dst, count, out, out_words);
  return int(cudaPeekAtLastError());
}
