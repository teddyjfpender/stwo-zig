// GPU-native TruthJob device ops (M8, design rv64-m8-gpu-native.md §3.3/§3.5;
// recursion range of gpu_native.Check). Enqueue only: no sync, no readback.
//
//   stwo_rv64_truth_params_gather_v1_on   kernel parameters from device
//       challenges/claims (jobs/truth_params.zig `gather` is the host model)
//   stwo_rv64_truth_status_v1_on          Check.truth_status (0x0301) / truth_root
//       (0x0307, stage 1: producer words only, no claims): every
//       truth producer verdict word, canonical claims, the local LogUp closure
//       (classic: claims[0]+claims[1]+claims[2] == 0 and the absent claim 4 is
//       zero; delegated: the local group claim is zero) — the checks the
//       legacy TruthWorker.complete / truth_source.generate / Components.init
//       run on the host after a readback
//   stwo_rv64_truth_root_match_v1_on      a Verdict for "count 8-word roots a == b"
//       (Check.root_match: FIXED root vs the class authority and the replayed
//       MAIN root vs the stage-1 root, in one word)
//   stwo_rv64_truth_channel_order_v1_on   Check.channel_order: the device
//       channel's status latch, cursor and chain equal the host's expectation
//   stwo_rv64_truth_pcs_status_v1_on      Check.pcs_status: the enqueue-only
//       PCS output header/status/channel words (hybrid_pcs.decodeWords' own
//       checks) and its trace roots equal the committed roots
//
// Every check writes exactly one Verdict word: 0 accepted, (check << 16) |
// detail rejected (gpu_native.zig Verdict). A check that never runs leaves the
// driver's `unset` word, which rejects.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kTruthStatus = 0x0301u;
constexpr uint32_t kChannelOrder = 0x0101u;
constexpr uint32_t kPcsStatus = 0x0207u;

__device__ __forceinline__ uint32_t reject(uint32_t check, uint32_t detail) {
  return (check << 16) | (detail ? (detail & 0xffffu) : 1u);
}
}  // namespace

struct TruthParamEntry {
  uint32_t source;
  uint32_t index;
};
static_assert(sizeof(TruthParamEntry) == 8, "truth parameter entry ABI");

// One thread per output word. A bad entry (unknown source / out of range)
// writes zeros and latches `status` (sticky, nonzero = reject).
__global__ void truth_params_gather(const uint32_t *staged, const uint32_t *local,
                                    const uint32_t *shared, const uint32_t *claims,
                                    const TruthParamEntry *entries, uint32_t count,
                                    uint4 bounds, uint32_t *out, uint32_t *status) {
  const uint64_t t = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x;
  if (t >= uint64_t(count) * 8) return;
  const TruthParamEntry e = entries[t / 8];
  const uint32_t w = uint32_t(t % 8);
  const uint32_t *src = nullptr;
  uint32_t limit = 0;
  switch (e.source) {
    case 0: src = staged; limit = bounds.x; break;
    case 1: src = local; limit = bounds.y; break;
    case 2: src = shared; limit = bounds.z; break;
    case 3: src = claims; limit = bounds.w; break;
    default: break;
  }
  if (!src || e.index >= limit) {
    out[t] = 0;
    atomicOr(status, 1u);
    return;
  }
  out[t] = src[uint64_t(e.index) * 8 + w];
}

struct TruthStatusConstants {
  uint32_t n_status;  // producer verdict words (witness, params, interactions, composition)
  uint32_t n_claims;  // claim felts (5 classic, 1 delegated)
  uint32_t n_zero;    // zero-check felts (local closing groups)
  uint32_t classic;   // 1: keccak closure over claims[0..3) and claims[4] == 0
  uint32_t check;     // verdict check id: 0x0301 truth_status (stage 2), 0x0307 truth_root (stage 1)
  uint32_t reserved[3];
};
static_assert(sizeof(TruthStatusConstants) == 32, "truth status constants ABI");

enum TruthDetail : uint32_t {
  kProducer = 1,       // + index of the first nonzero producer word (<< 8)
  kNoncanonicalClaim = 2,
  kLocalClosure = 3,
  kAbsentClaim = 4,
  kZeroGroup = 5,
  kRootMismatch = 6,
};

__global__ void truth_status(const uint32_t *status, const uint32_t *claims, const uint32_t *zero,
                             TruthStatusConstants c, uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  for (uint32_t i = 0; i < c.n_status && !detail; ++i)
    if (status[i] != 0) detail = kProducer | ((i & 0xffu) << 8);
  for (uint32_t i = 0; i < c.n_claims && !detail; ++i)
    if (!canonical(from_words(claims + 8 * i))) detail = kNoncanonicalClaim;
  if (!detail && c.classic) {
    const OM31 sum = add(add(from_words(claims), from_words(claims + 8)), from_words(claims + 16));
    if (!is_zero(sum)) detail = kLocalClosure;
    else if (c.n_claims > 4 && !is_zero(from_words(claims + 32))) detail = kAbsentClaim;
  }
  for (uint32_t i = 0; i < c.n_zero && !detail; ++i) {
    const OM31 z = from_words(zero + 8 * i);
    if (!canonical(z) || !is_zero(z)) detail = kZeroGroup;
  }
  verdict[0] = detail ? reject(c.check, detail) : 0u;
}

// `count` 8-word roots; detail = 1 + index of the first differing root.
__global__ void truth_root_match(const uint32_t *a, const uint32_t *b, uint32_t count, uint32_t check,
                                 uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  for (uint32_t i = 0; i < 8 * count && !detail; ++i)
    if (a[i] != b[i]) detail = 1 + i / 8;
  verdict[0] = detail ? reject(check, detail) : 0u;
}

// Channel state ABI (jobs/channel.zig Snapshot): digest[8], draws, cursor,
// status, reserved, chain (u64), padding[2].
__global__ void truth_channel_order(const uint32_t *state, uint32_t cursor, uint64_t chain,
                                    uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  const uint64_t got = uint64_t(state[12]) | (uint64_t(state[13]) << 32);
  uint32_t detail = 0;
  if (state[10] != 0) detail = 1;
  else if (state[11] != 0) detail = 2;
  else if (state[9] != cursor) detail = 3;
  else if (got != chain) detail = 4;
  else if (state[14] != 0 || state[15] != 0) detail = 5;
  verdict[0] = detail ? reject(kChannelOrder, detail) : 0u;
}

struct TruthPcsExpect {
  uint32_t header[14];   // expected header words (mask selects the compared ones)
  uint32_t header_mask;  // bit i: compare header[i]
  uint32_t trees;        // committed trees (roots compared with `roots`)
  uint32_t reserved[2];
};
static_assert(sizeof(TruthPcsExpect) == 72, "truth pcs expectation ABI");

// hybrid_pcs.decodeWords: header, numerical status word, 16 channel words,
// then trees * 8 roots.
__global__ void truth_pcs_status(const uint32_t *words, const uint32_t *roots, TruthPcsExpect x,
                                 uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  for (uint32_t i = 0; i < 14 && !detail; ++i)
    if (((x.header_mask >> i) & 1u) && words[i] != x.header[i]) detail = 1 + (i << 8);
  if (!detail && words[14] != 0) detail = 2;
  const uint32_t *state = words + 15;
  if (!detail && (state[9] != words[13] || state[10] != 0 || state[11] != 0 || state[12] != 17 + words[13]))
    detail = 3;
  for (uint32_t i = 13; i < 16 && !detail; ++i)
    if (state[i] != 0) detail = 3;
  const uint32_t *got = words + 31;
  for (uint32_t i = 0; i < 8 * x.trees && !detail; ++i)
    if (got[i] != roots[i]) detail = 4 + ((i / 8) << 8);
  verdict[0] = detail ? reject(kPcsStatus, detail) : 0u;
}
}  // namespace stwo::cuda::rv64

using stwo::cuda::rv64::RangeCustody;

extern "C" int stwo_rv64_truth_params_gather_v1_on(void *context, uint32_t lane, const uint32_t *staged,
                                                   const uint32_t *local, const uint32_t *shared,
                                                   const uint32_t *claims, const void *entries,
                                                   uint32_t count, const uint32_t bounds[4],
                                                   uint32_t *out, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!entries || !bounds || !count || count > 65536 || !staged || !shared) return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(out, uint64_t(count) * 8, true) || !custody.range(status, 1, true)) return custody.status;
  const uint4 b{bounds[0], local ? bounds[1] : 0u, bounds[2], claims ? bounds[3] : 0u};
  const uint32_t threads = 256, words = count * 8;
  truth_params_gather<<<(words + threads - 1) / threads, threads, 0, custody.stream>>>(
      staged, local, shared, claims, reinterpret_cast<const TruthParamEntry *>(entries), count, b, out, status);
  return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_truth_status_v1_on(void *context, uint32_t lane, const uint32_t *status,
                                            const uint32_t *claims, const uint32_t *zero,
                                            const void *constants, uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!constants) return int(cudaErrorInvalidValue);
  const auto c = *reinterpret_cast<const TruthStatusConstants *>(constants);
  if ((c.check != kTruthStatus && c.check != 0x0307u) || !c.n_status || c.n_status > 64 || c.n_claims > 8 || c.n_zero > 8 ||
      (c.classic && c.n_claims < 3) || (c.n_zero && !zero) || (c.n_claims && !claims))
    return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(status, c.n_status, false) ||
      (c.n_claims && !custody.range(claims, uint64_t(c.n_claims) * 8, false)) ||
      (c.n_zero && !custody.range(zero, uint64_t(c.n_zero) * 8, false)) || !custody.range(verdict, 1, true))
    return custody.status;
  truth_status<<<1, 1, 0, custody.stream>>>(status, claims, zero, c, verdict);
  return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_truth_root_match_v1_on(void *context, uint32_t lane, const uint32_t *a,
                                                const uint32_t *b, uint32_t count, uint32_t check,
                                                uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!check || check > 0xffffu || !count || count > 4) return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(a, uint64_t(count) * 8, false) || !custody.range(b, uint64_t(count) * 8, false) ||
      !custody.range(verdict, 1, true))
    return custody.status;
  truth_root_match<<<1, 1, 0, custody.stream>>>(a, b, count, check, verdict);
  return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_truth_channel_order_v1_on(void *context, uint32_t lane, const uint32_t *state,
                                                   uint32_t cursor, uint64_t chain, uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  RangeCustody<4> custody(context, lane);
  if (!custody.range(state, 16, false) || !custody.range(verdict, 1, true)) return custody.status;
  truth_channel_order<<<1, 1, 0, custody.stream>>>(state, cursor, chain, verdict);
  return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_truth_pcs_status_v1_on(void *context, uint32_t lane, const uint32_t *words,
                                                uint64_t n_words, const uint32_t *roots,
                                                const void *expect, uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!expect) return int(cudaErrorInvalidValue);
  const auto x = *reinterpret_cast<const TruthPcsExpect *>(expect);
  if (!x.trees || x.trees > 8 || n_words < 31 + uint64_t(x.trees) * 8) return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(words, 31 + uint64_t(x.trees) * 8, false) || !custody.range(roots, uint64_t(x.trees) * 8, false) ||
      !custody.range(verdict, 1, true))
    return custody.status;
  truth_pcs_status<<<1, 1, 0, custody.stream>>>(words, roots, x, verdict);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_truth_ops_version(void) {
  return 1;
}
