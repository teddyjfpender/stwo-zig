// Device Check.oods_constraint of a native segment (M8 GPU-native, design
// rv64-m8-gpu-native.md §3.5, inventory H11; stream native, piece gn-s2).
//
// Host reference: the retired native hybrid stageTwoInner's last check,
//   evalCompositionPolynomialAtPoint(oods, sampled_values, alpha, mask_log)
//     == extractCompositionOodsEvalWithSplit(oods, mask_log + split, split)
// over every role of the segment (gkr_local role_oods.zig and the other roles:
// acc = acc * alpha + residual / cosetVanishing(CanonicCoset(trace_log),
// p_local), p_local = the OODS point doubled down to the role's domain, plus
// the local-binding auxiliaries mle_point.evalAnchorsFor / evalCarryQuotientFor
// at p_local). The residuals are the role's composition program
// (secure_polynomial_program_v2, the DAG the AOT composition kernels are
// generated from) evaluated at the sampled masks. The per-class program
// (jobs/native_encode_oods.zig `build`) carries every role's node table with
// its mask reads resolved to PCS-image sample indices; parameters and hc rows
// are read from the composition table after its device patches. One block:
// one thread per role (roles are independent: each yields its Horner
// partial), then thread 0 folds the partials in order and compares with the
// composition samples' reconstruction. Exact OM31 arithmetic (om31.cuh is the
// host basis), so the verdict is the host's. Writes exactly one Verdict word
// (gpu_native.zig: 0 accepted, (0x0205 << 16) | detail rejected) and, when
// requested, [evaluated(8) | extracted(8)]. Enqueue only, no sync, no readback.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

struct StwoRv64NativeOodsIo {
  const uint32_t *desc;
  uint64_t desc_words;
  const uint32_t *samples;  // PCS image samples section, 8 words per sample
  uint64_t sample_words;
  const uint32_t *table;  // composition table (parameters + hc rows, patched)
  uint64_t table_words;
  const uint32_t *alpha;  // composition coefficient, 8 words
  const uint32_t *point;  // native_pcs OODS field (33 words): x[8] | y[8] | base x[8] y[8] | status
  uint32_t *scratch;      // registers (8 per node) + 9 per role
  uint64_t scratch_words;
  uint32_t *verdict;  // 1 word
  uint32_t *diag;     // 16 words [evaluated | extracted] or null
};
static_assert(sizeof(StwoRv64NativeOodsIo) == 96, "native OODS Io ABI");

namespace stwo::cuda::rv64::native_oods {
namespace {
constexpr uint32_t kCheck = 0x0205u;
constexpr uint32_t kThreads = 128;
constexpr uint32_t kMaxLog = 30;
constexpr uint32_t kNoTable = 0xffffffffu;
enum : uint32_t { hMagic = 0, hVersion = 1, hWords = 2, hRoles = 3, hGlobalLog = 4, hSplit = 5, hCompositionSample = 6,
                  hSamples = 7, hScratch = 8, hTable = 9, hHeader = 16 };
enum : uint32_t { rTraceLog = 0, rNNodes = 1, rNodesAt = 2, rNInputs = 3, rInputsAt = 4, rNConstants = 5, rConstantsAt = 6,
                  rNParams = 7, rParamsAt = 8, rNRoots = 9, rRootsAt = 10, rRegsAt = 11, rHcAt = 12, rFlags = 13,
                  rHalfStep = 14, rNPoints = 16, rPointsAt = 17, rWords = 32 };
enum : uint32_t { dDescriptor = 1, dNoncanonical = 2, dZeroInverse = 3, dMismatch = 4, dPoint = 5 };
enum : uint32_t { opConstant = 0, opInput = 1, opParameter = 2, opAdd = 3, opSub = 4, opMul = 5, opNeg = 6 };
enum : uint32_t { inSample = 0, inFirst = 1, inSecond = 2, inCarry = 3, inZero = 4 };
constexpr uint32_t kFlagAux = 1;

struct Pt {
  OM31 x, y;
};
__device__ __forceinline__ OM31 negate(OM31 a) {
  return sub(zero(), a);
}
__device__ __forceinline__ void store8(uint32_t *p, OM31 v) {
  for (uint32_t c = 0; c < 8; ++c) p[c] = coordinate(v, c);
}
__device__ __forceinline__ Pt padd(Pt a, Pt b) {
  return {sub(mul(a.x, b.x), mul(a.y, b.y)), add(mul(a.x, b.y), mul(a.y, b.x))};
}
// p - (x, y) for an M31 point: p + conjugate.
__device__ __forceinline__ Pt psub_m(Pt p, const uint32_t *c) {
  return padd(p, {base(c[0]), base(c[1] ? q::kPrime - c[1] : 0u)});
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
// M31 value of 2^k (2^31 = 1 mod p).
__device__ __forceinline__ uint32_t pow2(uint32_t k) {
  return 1u << (k % 31u);
}
__device__ __forceinline__ OM31 double_x(OM31 x) {
  const OM31 s = mul(x, x);
  return sub(add(s, s), one());
}
// core/constraints.zig cosetVanishing over h = p - initial(-shift): (h + half_step).x, doubled log - 1 times.
__device__ __forceinline__ OM31 vanish(Pt h, const uint32_t *half, uint32_t log) {
  OM31 x = padd(h, {base(half[0]), base(half[1])}).x;
  for (uint32_t i = 1; i < log; ++i) x = double_x(x);
  return x;
}
// mle_point.evalIsFirstFor(coset, p + s) with c = initial - s: num / (pointVanishing(initial, p + s) * 2^log).
__device__ bool is_first(Pt p, const uint32_t *c, const uint32_t *half, uint32_t log, OM31 *out) {
  const Pt h = psub_m(p, c);
  const OM31 num = vanish(h, half, log);
  const OM31 onepx = add(one(), h.x);
  if (is_zero(onepx)) return false;
  const OM31 den = scale(mul(h.y, inverse_nonzero(onepx)), pow2(log));
  if (is_zero(den)) return false;
  *out = mul(num, inverse_nonzero(den));
  return true;
}
// mle_point.evalStepSelectorFor(coset, log_step, p - shift) with c = initial + shift.
__device__ bool step_selector(Pt p, const uint32_t *c, uint32_t log, uint32_t log_step, OM31 *out) {
  Pt q = psub_m(p, c);
  OM31 ys[kMaxLog];
  for (uint32_t i = 0; i < log; ++i) {
    ys[i] = q.y;
    q = padd(q, q);
  }
  OM31 v0 = ys[log - 1], inv1 = zero(), sum = zero();
  if (is_zero(v0)) return false;
  for (uint32_t i = 1; i < log_step; ++i) {
    const OM31 v = ys[log - 1 - i];
    if (is_zero(v)) return false;
    const OM31 iv = inverse_nonzero(v);
    if (i == 1) inv1 = iv;
    sum = add(sum, iv);
  }
  const OM31 t = mul(v0, inv1);
  const OM31 numer = add(mul(t, t), mul(v0, add(sum, sum)));
  *out = scale(numer, q::inverse(pow2(log_step + 1)));
  return true;
}
// QM31 fromPartialEvals: x0 + x1 i + x2 u + x3 iu.
__device__ __forceinline__ q::QM31 qpe(q::QM31 x0, q::QM31 x1, q::QM31 x2, q::QM31 x3) {
  const q::QM31 I{{0u, 1u}, {0u, 0u}}, U{{0u, 0u}, {1u, 0u}}, IU{{0u, 0u}, {0u, 1u}};
  return q::add(q::add(x0, q::mul(x1, I)), q::add(q::mul(x2, U), q::mul(x3, IU)));
}
// om31.zig fromPartialEvals (same as outer_checks.cu).
__device__ OM31 from_partial_evals_om31(const OM31 e[8]) {
  const q::QM31 l0 = qpe(e[0].c0, e[1].c0, e[2].c0, e[3].c0), l1 = qpe(e[0].c1, e[1].c1, e[2].c1, e[3].c1);
  const q::QM31 u0 = qpe(e[4].c0, e[5].c0, e[6].c0, e[7].c0), u1 = qpe(e[4].c1, e[5].c1, e[6].c1, e[7].c1);
  return {q::add(l0, mul_u(u1)), q::add(l1, u0)};
}
__device__ __forceinline__ void refuse(uint32_t *fail, uint32_t detail) {
  atomicMin(fail, detail);
}
// Reads an 8-word felt; false if non-canonical.
__device__ __forceinline__ bool felt(const uint32_t *w, OM31 *out) {
  *out = from_words(w);
  return canonical(*out);
}

// One role: Horner partial over its roots, times its inverse coset vanishing.
__device__ void role_partial(const StwoRv64NativeOodsIo &io, const uint32_t *row, Pt point, OM31 alpha, uint32_t *out,
                             uint32_t *fail) {
  const uint32_t *d = io.desc;
  const uint32_t log = row[rTraceLog];
  Pt local = point;
  for (uint32_t i = log; i < d[hGlobalLog]; ++i) local = padd(local, local);
  const uint32_t *half = row + rHalfStep;
  const uint32_t *pts = d + row[rPointsAt];
  const OM31 den = vanish(psub_m(local, pts), half, log);
  if (is_zero(den)) return refuse(fail, dZeroInverse);
  const OM31 inv = inverse_nonzero(den);
  OM31 aux[3] = {zero(), zero(), zero()};
  if (row[rFlags] & kFlagAux) {
    if (log < 2 || log > kMaxLog || row[rNPoints] != 4 + 2 * (log - 1) || row[rHcAt] == kNoTable ||
        uint64_t(row[rHcAt]) + 16ull * log > io.table_words)
      return refuse(fail, dDescriptor);
    if (!is_first(local, pts, half, log, &aux[0]) || !is_first(local, pts + 2, half, log, &aux[1]))
      return refuse(fail, dZeroInverse);
    const uint32_t *hc = io.table + row[rHcAt];
    OM31 carry = zero();
    for (uint32_t v = 0; v + 1 < log; ++v) {
      OM31 s0, s1, h0, h1;
      if (!step_selector(local, pts + 2 * (4 + 2 * v), log, v + 2, &s0) ||
          !step_selector(local, pts + 2 * (5 + 2 * v), log, v + 2, &s1))
        return refuse(fail, dZeroInverse);
      if (!felt(hc + 8 * v, &h0) || !felt(hc + 8 * (log + v), &h1)) return refuse(fail, dNoncanonical);
      carry = add(add(carry, mul(s0, h0)), mul(s1, h1));
    }
    OM31 last0, first1, h0, h1;
    if (!is_first(local, pts + 4, half, log, &last0) || !is_first(local, pts + 6, half, log, &first1))
      return refuse(fail, dZeroInverse);
    if (!felt(hc + 8 * (log - 1), &h0) || !felt(hc + 8 * (2 * log - 1), &h1)) return refuse(fail, dNoncanonical);
    aux[2] = add(add(carry, mul(h0, last0)), mul(h1, first1));
  }
  OM31 *regs = reinterpret_cast<OM31 *>(io.scratch + row[rRegsAt]);
  const uint32_t n = row[rNNodes];
  const uint32_t *nodes = d + row[rNodesAt];
  const uint32_t *inputs = d + row[rInputsAt];
  const uint32_t *consts = d + row[rConstantsAt];
  const uint32_t n_samples = d[hSamples];
  for (uint32_t k = 0; k < n; ++k, nodes += 4) {
    const uint32_t op = nodes[0], lhs = nodes[1], rhs = nodes[2], value = nodes[3];
    OM31 v;
    switch (op) {
      case opConstant:
        if (value >= row[rNConstants]) return refuse(fail, dDescriptor);
        if (!felt(consts + 8 * value, &v)) return refuse(fail, dNoncanonical);
        break;
      case opParameter:
        if (value >= row[rNParams] || uint64_t(row[rParamsAt]) + 8ull * (uint64_t(value) + 1) > io.table_words)
          return refuse(fail, dDescriptor);
        if (!felt(io.table + row[rParamsAt] + 8 * value, &v)) return refuse(fail, dNoncanonical);
        break;
      case opInput: {
        if (value >= row[rNInputs]) return refuse(fail, dDescriptor);
        const uint32_t kind = inputs[2 * value], index = inputs[2 * value + 1];
        switch (kind) {
          case inSample:
            if (index >= n_samples) return refuse(fail, dDescriptor);
            if (!felt(io.samples + 8ull * index, &v)) return refuse(fail, dNoncanonical);
            break;
          case inFirst: v = aux[0]; break;
          case inSecond: v = aux[1]; break;
          case inCarry: v = aux[2]; break;
          case inZero: v = zero(); break;
          default: return refuse(fail, dDescriptor);
        }
        break;
      }
      case opAdd:
      case opSub:
      case opMul:
        if (lhs >= k || rhs >= k) return refuse(fail, dDescriptor);
        v = op == opAdd ? add(regs[lhs], regs[rhs]) : op == opSub ? sub(regs[lhs], regs[rhs]) : mul(regs[lhs], regs[rhs]);
        break;
      case opNeg:
        if (lhs >= k) return refuse(fail, dDescriptor);
        v = negate(regs[lhs]);
        break;
      default:
        return refuse(fail, dDescriptor);
    }
    regs[k] = v;
  }
  OM31 h = zero();
  const uint32_t *roots = d + row[rRootsAt];
  for (uint32_t k = 0; k < row[rNRoots]; ++k) {
    if (roots[k] >= n) return refuse(fail, dDescriptor);
    h = add(mul(h, alpha), mul(regs[roots[k]], inv));
  }
  store8(out, h);
  out[8] = 1;
}

__global__ void __launch_bounds__(kThreads) native_oods_check(StwoRv64NativeOodsIo io) {
  __shared__ uint32_t fail;
  const uint32_t tid = threadIdx.x;
  const uint32_t *d = io.desc;
  if (tid == 0) fail = 0xffffffffu;
  __syncthreads();
  const uint32_t roles = d[hRoles];
  const bool head = d[hMagic] == 0x31444f4eu && d[hVersion] == 1 && d[hWords] == io.desc_words && roles &&
                    hHeader + uint64_t(roles) * rWords <= io.desc_words && uint64_t(d[hSamples]) * 8 <= io.sample_words &&
                    uint64_t(d[hScratch]) <= io.scratch_words && uint64_t(d[hScratch]) >= 9ull * roles &&
                    d[hTable] <= io.table_words && d[hSplit] >= 1 && d[hSplit] <= 4 && d[hGlobalLog] >= 1 &&
                    d[hGlobalLog] < 31 && uint64_t(d[hCompositionSample]) + (8ull << d[hSplit]) <= d[hSamples];
  if (!head) {
    if (tid == 0) io.verdict[0] = (kCheck << 16) | dDescriptor;
    return;
  }
  OM31 alpha;
  Pt point;
  const bool canon = felt(io.alpha, &alpha) && felt(io.point, &point.x) && felt(io.point + 8, &point.y);
  if (tid == 0) {
    if (!canon) refuse(&fail, dNoncanonical);
    // The device point build's status word (host: InvalidStructure).
    if (io.point[32]) refuse(&fail, dPoint);
  }
  const uint64_t regs_end = uint64_t(d[hScratch]) - 9ull * roles;
  uint32_t *partials = io.scratch + regs_end;
  if (canon)
    for (uint32_t p = tid; p < roles; p += kThreads) {
      const uint32_t *row = d + hHeader + p * rWords;
      partials[9 * p + 8] = 0;
      const bool spans = uint64_t(row[rNodesAt]) + 4ull * row[rNNodes] <= io.desc_words &&
                         uint64_t(row[rInputsAt]) + 2ull * row[rNInputs] <= io.desc_words &&
                         uint64_t(row[rConstantsAt]) + 8ull * row[rNConstants] <= io.desc_words &&
                         uint64_t(row[rRootsAt]) + row[rNRoots] <= io.desc_words &&
                         uint64_t(row[rPointsAt]) + 2ull * row[rNPoints] <= io.desc_words && row[rNPoints] >= 1 &&
                         uint64_t(row[rRegsAt]) + 8ull * row[rNNodes] <= regs_end && row[rTraceLog] >= 1 &&
                         row[rTraceLog] <= d[hGlobalLog] && row[rTraceLog] <= kMaxLog;
      if (!spans) {
        refuse(&fail, dDescriptor);
        continue;
      }
      role_partial(io, row, point, alpha, partials + 9 * p, &fail);
    }
  __syncthreads();
  if (tid) return;
  OM31 acc = zero();
  for (uint32_t p = 0; p < roles && fail == 0xffffffffu; ++p) {
    const uint32_t *row = d + hHeader + p * rWords;
    if (!partials[9 * p + 8]) {
      refuse(&fail, dDescriptor);
      break;
    }
    acc = add(mul(acc, power(alpha, row[rNRoots])), from_words(partials + 9 * p));
  }
  // proof_family.zig reconstructCompositionChunkEvals.
  OM31 chunk[16];
  const uint32_t n_chunks = 1u << d[hSplit];
  for (uint32_t c = 0; c < n_chunks && fail == 0xffffffffu; ++c) {
    OM31 e[8];
    for (uint32_t k = 0; k < 8; ++k)
      if (!felt(io.samples + 8ull * (d[hCompositionSample] + c * 8 + k), &e[k])) refuse(&fail, dNoncanonical);
    chunk[c] = from_partial_evals_om31(e);
  }
  uint32_t word = 0;
  if (fail != 0xffffffffu) {
    word = (kCheck << 16) | fail;
  } else {
    uint32_t active = n_chunks, parent_log = d[hGlobalLog] + 1;
    while (active > 1) {
      Pt f = point;
      for (uint32_t i = 0; i + 2 < parent_log; ++i) f = padd(f, f);
      for (uint32_t i = 0, o = 0; i < active; i += 2, ++o) chunk[o] = add(chunk[i], mul(f.x, chunk[i + 1]));
      active >>= 1;
      ++parent_log;
    }
    if (io.diag) {
      store8(io.diag, acc);
      store8(io.diag + 8, chunk[0]);
    }
    bool eq = true;
    for (uint32_t c = 0; c < 8; ++c) eq = eq && coordinate(acc, c) == coordinate(chunk[0], c);
    if (!eq) word = (kCheck << 16) | dMismatch;
  }
  io.verdict[0] = word;
}
}  // namespace
}  // namespace stwo::cuda::rv64::native_oods

extern "C" int stwo_rv64_native_oods_check_v1_on(void *context, uint32_t lane, const StwoRv64NativeOodsIo *io) {
  using namespace stwo::cuda::rv64;
  if (!io || !io->desc || io->desc_words < 16 || !io->samples || !io->sample_words || (!io->table && io->table_words) ||
      !io->alpha || !io->point || !io->scratch || !io->scratch_words || !io->verdict)
    return int(cudaErrorInvalidValue);
  RangeCustody<9> custody(context, lane);
  const bool ok = custody.range(io->desc, io->desc_words, false) && custody.range(io->samples, io->sample_words, false) &&
                  (!io->table_words || custody.range(io->table, io->table_words, false)) &&
                  custody.range(io->alpha, 8, false) && custody.range(io->point, 33, false) &&
                  custody.range(io->scratch, io->scratch_words, true) && custody.range(io->verdict, 1, true) &&
                  (!io->diag || custody.range(io->diag, 16, true));
  if (!ok) return custody.status ? custody.status : int(cudaErrorInvalidValue);
  native_oods::native_oods_check<<<1, native_oods::kThreads, 0, custody.stream>>>(*io);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_native_oods_check_version(void) {
  return 1;
}
