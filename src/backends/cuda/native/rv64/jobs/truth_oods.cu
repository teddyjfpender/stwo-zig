// Device OODS constraint check of a truth proof (M8 GPU-native, stream
// gn-truth; design rv64-m8-gpu-native.md §3.5, inventory H14/H22 for truths).
//
// Host reference: truth_job.zig Stage2.assemble (the legacy W.Prover tail):
//   expected  = Components.evalCompositionPolynomialAtPoint(oods, sampled,
//               alpha, mask_log)   (every truth role in component order; each
//               role's constraints Horner-accumulated with alpha and scaled
//               by 1 / cosetVanishing(trace coset, oods doubled to the role))
//   extracted = proof.extractCompositionOodsEvalWithSplit(oods,
//               mask_log + split, split)
//   accept iff expected == extracted (else ConstraintsNotSatisfied).
//
// On the device the same computation runs from a per-class descriptor built
// at warm (jobs/truth_oods.zig): every role's secure_polynomial_program_v2
// (the program the AOT truth composition kernel is generated from) with its
// mask reads resolved to PCS-image sample indices and the classic last-anchor
// public polynomial marked. Per proof the kernel reads the PCS image samples,
// the device-gathered composition parameters (the same words the composition
// kernel read), the composition coefficient alpha and the drawn OODS point.
// Exact OM31 arithmetic (om31.cuh is the host basis): the verdict is the
// host's verdict. Two launches on the lane's exec stream: one block per role
// (DAG levels in parallel, then the role's Horner partial), then one thread
// folds the partials, reconstructs the composition value and writes one
// Verdict word plus a 16-word diagnostic [evaluated(8) | extracted(8)].
// Enqueue only, no sync, no readback.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

struct StwoRv64TruthOodsIo {
  const uint32_t *desc;
  uint64_t desc_words;
  const uint32_t *samples;  // PCS image samples section, 8 words per sample
  uint64_t sample_words;
  const uint32_t *params[3];  // per role: gathered composition parameters (8 words each)
  uint64_t param_words[3];
  const uint32_t *alpha;  // 8 words
  const uint32_t *point;  // native_pcs OODS field (33 words): x[8] | y[8] | base x[8] y[8] | status
  uint32_t *scratch;
  uint64_t scratch_words;
  uint32_t *verdict;  // 1 word
  uint32_t *diag;     // 16 words [evaluated | extracted] or null
};
static_assert(sizeof(StwoRv64TruthOodsIo) == 128, "truth OODS Io ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kTruthOods = 0x0308u;
constexpr uint32_t kThreads = 256;
// Header (jobs/truth_oods.zig H, same order).
enum : uint32_t { hMagic = 0, hVersion = 1, hWords = 2, hRoles = 3, hGlobalLog = 4, hCompositionLog = 5, hSplit = 6,
                  hCompositionSample = 7, hSamples = 8, hConstsAt = 9, hNConsts = 10, hScratch = 11, hPartialsAt = 12,
                  hHeader = 16 };
// Role rows (jobs/truth_oods.zig R).
enum : uint32_t { rTraceLog = 0, rNodesAt = 1, rNNodes = 2, rLevelsAt = 3, rNLevels = 4, rRootsAt = 5, rNRoots = 6,
                  rRegsAt = 7, rNParams = 8, rAnchor = 9, rInitial = 10, rHalfStep = 12, rStep = 14, rWords = 16 };
enum : uint32_t { opInput = 0, opAnchor = 1, opConstant = 2, opParameter = 3, opAdd = 4, opSub = 5, opMul = 6, opNeg = 7 };
enum : uint32_t { dDescriptor = 1, dNoncanonical = 2, dZeroInverse = 3, dMismatch = 4, dPoint = 5, dParams = 6 };
constexpr uint32_t kNodeWords = 4;
constexpr uint32_t kPartialWords = 16;  // value[8] | done | detail

struct Pt {
  OM31 x, y;
};
__device__ __forceinline__ Pt padd(Pt a, Pt b) {
  return {sub(mul(a.x, b.x), mul(a.y, b.y)), add(mul(a.x, b.y), mul(a.y, b.x))};
}
__device__ __forceinline__ Pt mpoint(uint32_t x, uint32_t y) {
  return {base(x), base(y)};
}
__device__ __forceinline__ uint32_t mneg(uint32_t v) {
  return v ? q::kPrime - v : 0u;
}
__device__ __forceinline__ void store8(uint32_t *p, OM31 v) {
  for (uint32_t c = 0; c < 8; ++c) p[c] = coordinate(v, c);
}
__device__ __forceinline__ OM31 power(OM31 x, uint32_t n) {
  OM31 out = one(), b = x;
  while (n) {
    if (n & 1u) out = mul(out, b);
    n >>= 1;
    if (n) b = mul(b, b);
  }
  return out;
}
// QM31 fromPartialEvals: x0 + x1 i + x2 u + x3 iu.
__device__ __forceinline__ q::QM31 qpe(q::QM31 x0, q::QM31 x1, q::QM31 x2, q::QM31 x3) {
  const q::QM31 I{{0u, 1u}, {0u, 0u}}, U{{0u, 0u}, {1u, 0u}}, IU{{0u, 0u}, {0u, 1u}};
  return q::add(q::add(x0, q::mul(x1, I)), q::add(q::mul(x2, U), q::mul(x3, IU)));
}
// om31.zig fromPartialEvals (outer_checks.cu, same basis).
__device__ OM31 from_partial_evals(const OM31 e[8]) {
  const q::QM31 l0 = qpe(e[0].c0, e[1].c0, e[2].c0, e[3].c0), l1 = qpe(e[0].c1, e[1].c1, e[2].c1, e[3].c1);
  const q::QM31 u0 = qpe(e[4].c0, e[5].c0, e[6].c0, e[7].c0), u1 = qpe(e[4].c1, e[5].c1, e[6].c1, e[7].c1);
  return {q::add(l0, mul_u(u1)), q::add(l1, u0)};
}
// core/constraints.zig cosetVanishing: p - initial + half_step, then doubleX.
__device__ __forceinline__ OM31 coset_vanishing(const uint32_t *row, Pt p) {
  p = padd(p, mpoint(row[rInitial], mneg(row[rInitial + 1])));
  p = padd(p, mpoint(row[rHalfStep], row[rHalfStep + 1]));
  OM31 x = p.x;
  for (uint32_t i = 1; i < row[rTraceLog]; ++i) x = sub(add(mul(x, x), mul(x, x)), one());
  return x;
}

__device__ __forceinline__ bool ok_header(const StwoRv64TruthOodsIo &io) {
  const uint32_t *d = io.desc;
  return d[hMagic] == 0x53444f54u && d[hVersion] == 1 && d[hWords] == io.desc_words && d[hRoles] >= 1 &&
         d[hRoles] <= 3 && hHeader + uint64_t(d[hRoles]) * rWords <= io.desc_words &&
         uint64_t(d[hSamples]) * 8 <= io.sample_words && d[hSplit] >= 1 && d[hSplit] <= 4 &&
         d[hCompositionLog] > d[hSplit] && d[hGlobalLog] < 31 &&
         uint64_t(d[hCompositionSample]) + (8ull << d[hSplit]) <= d[hSamples] && d[hScratch] <= io.scratch_words &&
         uint64_t(d[hPartialsAt]) + kPartialWords * 3ull <= d[hScratch] &&
         uint64_t(d[hConstsAt]) + 8ull * d[hNConsts] <= io.desc_words;
}

// One block per role: DAG levels in parallel, then thread 0's Horner partial
// (sum over the role's constraints of alpha^(n-1-k) * c_k * inv).
__global__ void __launch_bounds__(kThreads) truth_oods_role(StwoRv64TruthOodsIo io) {
  __shared__ uint32_t fail;
  __shared__ uint32_t anchor_words[8];
  const uint32_t tid = threadIdx.x, r = blockIdx.x;
  const uint32_t *d = io.desc;
  if (!ok_header(io) || r >= d[hRoles]) return;  // the fold refuses (partial not done)
  uint32_t *partial = io.scratch + d[hPartialsAt] + kPartialWords * r;
  const uint32_t *row = d + hHeader + r * rWords;
  const uint64_t n_nodes = row[rNNodes];
  const bool shape = row[rTraceLog] >= 1 && row[rTraceLog] <= d[hGlobalLog] && n_nodes >= 1 && row[rNRoots] >= 1 &&
                     uint64_t(row[rNodesAt]) + kNodeWords * n_nodes <= io.desc_words &&
                     uint64_t(row[rLevelsAt]) + row[rNLevels] + 1 <= io.desc_words &&
                     uint64_t(row[rRootsAt]) + row[rNRoots] <= io.desc_words &&
                     uint64_t(row[rRegsAt]) + 8 * n_nodes <= d[hPartialsAt] && r < 3 &&
                     uint64_t(row[rNParams]) * 8 <= io.param_words[r] && (row[rNParams] == 0 || io.params[r]);
  if (tid == 0) {
    fail = shape ? 0u : dDescriptor;
    if (!shape) {
      partial[8] = 1;
      partial[9] = dDescriptor;
    }
  }
  __syncthreads();
  if (!shape) return;
  const Pt point{from_words(io.point), from_words(io.point + 8)};
  Pt local = point;
  for (uint32_t i = row[rTraceLog]; i < d[hGlobalLog]; ++i) local = padd(local, local);
  if (tid == 0 && row[rAnchor]) {
    // logup_gkr/mle_point.zig evalIsFirstFor(coset, local + step):
    //   cosetVanishing(coset, p) / (pointVanishing(initial, p) * 2^log),
    //   pointVanishing(v, p) = h.y / (1 + h.x), h = p - v.
    const Pt p = padd(local, mpoint(row[rStep], row[rStep + 1]));
    const OM31 num = coset_vanishing(row, p);
    const Pt h = padd(p, mpoint(row[rInitial], mneg(row[rInitial + 1])));
    const OM31 hx1 = add(h.x, one());
    OM31 a = zero();
    if (is_zero(hx1) || is_zero(h.y)) fail = dZeroInverse;
    else {
      const OM31 pv = mul(h.y, inverse_nonzero(hx1));
      const OM31 den = scale(pv, uint32_t((1ull << row[rTraceLog]) % q::kPrime));
      if (is_zero(den)) fail = dZeroInverse;
      else a = mul(num, inverse_nonzero(den));
    }
    store8(anchor_words, a);
  }
  __syncthreads();
  if (fail) {
    if (tid == 0) {
      partial[8] = 1;
      partial[9] = fail;
    }
    return;
  }
  const OM31 anchor = from_words(anchor_words);
  const uint32_t *nodes = d + row[rNodesAt];
  const uint32_t *levels = d + row[rLevelsAt];
  uint32_t *regs = io.scratch + row[rRegsAt];
  const uint32_t n_samples = d[hSamples];
  for (uint32_t l = 0; l < row[rNLevels]; ++l) {
    const uint32_t begin = levels[l], end = levels[l + 1];
    if (begin > end || end > n_nodes) {
      if (tid == 0) fail = dDescriptor;
      break;
    }
    for (uint32_t i = begin + tid; i < end; i += kThreads) {
      const uint32_t *n = nodes + kNodeWords * i;
      const uint32_t op = n[0], a = n[1], b = n[2];
      OM31 v = zero();
      bool bad = false;
      switch (op) {
        case opInput:
          if (a >= n_samples) bad = true;
          else v = from_words(io.samples + 8ull * a);
          break;
        case opAnchor:
          v = anchor;
          break;
        case opConstant:
          if (a >= d[hNConsts]) bad = true;
          else v = from_words(d + d[hConstsAt] + 8ull * a);
          break;
        case opParameter:
          if (a >= row[rNParams]) bad = true;
          else v = from_words(io.params[r] + 8ull * a);
          break;
        case opAdd: case opSub: case opMul:
          if (a >= begin || b >= begin) bad = true;  // operands strictly in earlier levels
          else {
            const OM31 x = from_words(regs + 8ull * a), y = from_words(regs + 8ull * b);
            v = op == opAdd ? add(x, y) : op == opSub ? sub(x, y) : mul(x, y);
          }
          break;
        case opNeg:
          if (a >= begin) bad = true;
          else v = sub(zero(), from_words(regs + 8ull * a));
          break;
        default:
          bad = true;
      }
      if (bad) atomicMax(&fail, uint32_t(dDescriptor));
      store8(regs + 8ull * i, v);
    }
    __syncthreads();
    if (fail) break;
  }
  __syncthreads();
  if (fail) {
    if (tid == 0) {
      partial[8] = 1;
      partial[9] = fail;
    }
    return;
  }
  // Horner over the roots in parallel: thread t folds a contiguous chunk
  //   P_t = sum_{k in chunk t} alpha^(end_t - 1 - k) * v_k,
  // thread 0 joins the chunks (acc = acc * alpha^len_t + P_t) and scales by
  // the role's 1/vanishing once. Exact field arithmetic: identical to the
  // host's per-constraint sum of alpha^(n-1-k) * (v_k * inv).
  __shared__ uint32_t chunk_words[kThreads * 8];
  __shared__ uint32_t bad_root;
  if (tid == 0) bad_root = 0;
  __syncthreads();
  const OM31 alpha = from_words(io.alpha);
  const uint32_t *roots = d + row[rRootsAt];
  const uint32_t n_roots = row[rNRoots];
  const uint32_t per = (n_roots + kThreads - 1) / kThreads;
  {
    const uint32_t begin = tid * per, end = begin + per < n_roots ? begin + per : n_roots;
    OM31 h = zero();
    for (uint32_t k = begin; k < end; ++k) {
      if (roots[k] >= n_nodes) {
        bad_root = 1;
        break;
      }
      h = add(mul(h, alpha), from_words(regs + 8ull * roots[k]));
    }
    store8(chunk_words + 8 * tid, h);
  }
  __syncthreads();
  if (tid) return;
  if (bad_root) {
    partial[8] = 1;
    partial[9] = dDescriptor;
    return;
  }
  const OM31 vanishing = coset_vanishing(row, local);
  if (is_zero(vanishing)) {
    partial[8] = 1;
    partial[9] = dZeroInverse;
    return;
  }
  const OM31 step = power(alpha, per);
  OM31 acc = zero();
  for (uint32_t t = 0; t < kThreads; ++t) {
    const uint32_t begin = t * per;
    if (begin >= n_roots) break;
    const uint32_t len = begin + per < n_roots ? per : n_roots - begin;
    acc = add(mul(acc, len == per ? step : power(alpha, len)), from_words(chunk_words + 8 * t));
  }
  store8(partial, mul(acc, inverse_nonzero(vanishing)));
  partial[9] = 0;
  partial[8] = 1;
}

__global__ void truth_oods_fold(StwoRv64TruthOodsIo io) {
  if (blockIdx.x || threadIdx.x) return;
  const uint32_t *d = io.desc;
  if (!ok_header(io)) {
    io.verdict[0] = (kTruthOods << 16) | dDescriptor;
    return;
  }
  uint32_t detail = 0;
  const Pt point{from_words(io.point), from_words(io.point + 8)};
  const OM31 alpha = from_words(io.alpha);
  if (!canonical(point.x) || !canonical(point.y) || !canonical(alpha)) detail = dNoncanonical;
  // The device point build's status word (host finish: the PCS decode fails).
  if (!detail && io.point[32]) detail = dPoint;
  for (uint32_t r = 0; r < d[hRoles] && !detail; ++r) {
    const uint32_t *row = d + hHeader + r * rWords;
    for (uint32_t i = 0; i < row[rNParams] && !detail; ++i)
      if (!canonical(from_words(io.params[r] + 8ull * i))) detail = dParams;
  }
  OM31 acc = zero();
  for (uint32_t r = 0; r < d[hRoles] && !detail; ++r) {
    const uint32_t *partial = io.scratch + d[hPartialsAt] + kPartialWords * r;
    if (partial[8] != 1) detail = dDescriptor;
    else if (partial[9]) detail = partial[9];
    else acc = add(mul(acc, power(alpha, d[hHeader + r * rWords + rNRoots])), from_words(partial));
  }
  // Composition samples: chunk c coordinates k at composition column c*8+k
  // (core/proof_family.zig extractCompositionOodsEvalWithSplit).
  OM31 chunk[16];
  const uint32_t chunks = 1u << d[hSplit];
  for (uint32_t c = 0; c < chunks; ++c) {
    OM31 e[8];
    for (uint32_t k = 0; k < 8; ++k) e[k] = from_words(io.samples + 8ull * (d[hCompositionSample] + c * 8 + k));
    chunk[c] = from_partial_evals(e);
  }
  uint32_t active = chunks, parent_log = d[hCompositionLog] - d[hSplit] + 1;
  while (active > 1) {
    Pt f = point;
    for (uint32_t i = 0; i + 2 < parent_log; ++i) f = padd(f, f);
    for (uint32_t i = 0, o = 0; i < active; i += 2, ++o) chunk[o] = add(chunk[i], mul(f.x, chunk[i + 1]));
    active /= 2;
    parent_log += 1;
  }
  const OM31 extracted = chunk[0];
  if (io.diag && !detail) {
    store8(io.diag, acc);
    store8(io.diag + 8, extracted);
  }
  if (!detail) {
    bool eq = true;
    for (uint32_t c = 0; c < 8; ++c) eq = eq && coordinate(acc, c) == coordinate(extracted, c);
    if (!eq) detail = dMismatch;
  }
  io.verdict[0] = detail ? ((kTruthOods << 16) | detail) : 0u;
  // Reset the partial flags so a stale scratch never satisfies a later check.
  for (uint32_t r = 0; r < d[hRoles]; ++r) io.scratch[d[hPartialsAt] + kPartialWords * r + 8] = 0;
}
}  // namespace
}  // namespace stwo::cuda::rv64

// All pointers are job-arena / slab / class-persistent memory of `context`
// (custody-checked); stream = the lane's exec stream. The scratch partial
// flags must be zero before the first launch (the caller memsets scratch).
extern "C" int stwo_rv64_truth_oods_check_v1_on(void *context, uint32_t lane, const StwoRv64TruthOodsIo *io) {
  using namespace stwo::cuda::rv64;
  if (!io || !io->desc || io->desc_words < hHeader || !io->samples || !io->sample_words || !io->alpha || !io->point ||
      !io->scratch || !io->scratch_words || !io->verdict)
    return int(cudaErrorInvalidValue);
  RangeCustody<12> custody(context, lane);
  bool ok = custody.range(io->desc, io->desc_words, false) && custody.range(io->samples, io->sample_words, false) &&
            custody.range(io->alpha, 8, false) && custody.range(io->point, 33, false) &&
            custody.range(io->scratch, io->scratch_words, true) && custody.range(io->verdict, 1, true) &&
            (!io->diag || custody.range(io->diag, 16, true));
  for (uint32_t r = 0; r < 3 && ok; ++r)
    if (io->params[r]) ok = io->param_words[r] && custody.range(io->params[r], io->param_words[r], false);
  if (!ok) return custody.status ? custody.status : int(cudaErrorInvalidValue);
  // Roles from the descriptor header are read on the device; the grid is the
  // contract maximum (3) and surplus blocks return at once.
  truth_oods_role<<<3, kThreads, 0, custody.stream>>>(*io);
  truth_oods_fold<<<1, 32, 0, custody.stream>>>(*io);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_truth_oods_version(void) {
  return 1;
}

// Verdict merge (truth stage 2, device encode): out = the first
// non-accepted word of words[0..n) (an unset word rejects, so it propagates),
// 0 when all accepted. Used to fold the truth's own PCS status check and the
// encoder's PCS status into the published Check.pcs_status word.
namespace stwo::cuda::rv64 {
namespace {
__global__ void truth_verdict_merge(const uint32_t *words, uint32_t n, uint32_t *out) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t v = 0;
  for (uint32_t i = 0; i < n && !v; ++i) v = words[i];
  out[0] = v;
}
}  // namespace
}  // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_truth_verdict_merge_v1_on(void *context, uint32_t lane, const uint32_t *words, uint32_t n,
                                                   uint32_t check, uint32_t *out) {
  using namespace stwo::cuda::rv64;
  (void)check;
  if (!n || n > 64) return int(cudaErrorInvalidValue);
  RangeCustody<2> custody(context, lane);
  if (!custody.range(words, n, false) || !custody.range(out, 1, true)) return custody.status;
  truth_verdict_merge<<<1, 1, 0, custody.stream>>>(words, n, out);
  return int(cudaPeekAtLastError());
}
