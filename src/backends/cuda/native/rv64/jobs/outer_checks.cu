// Device acceptance checks of an outer (leaf / fold / root) node (M8 GPU-native,
// design rv64-m8-gpu-native.md §3.5; recursion range of gpu_native.Check).
//
// lookup_sum (Check 0x0302): the node's LogUp closure, on device, from the
// node's own outer slab section (canonical claims, z, alpha written by the
// node body) and its expected public outputs (staged node region). Host
// reference: circuit_cpu/om31/witness.zig lookupSum, called by
// jobs/outer_job.zig decode():
//
//   sum = sum_c claims[c]
//       + sum_i 1 / combine(GATE, U_VAR_IDX + 1 + i, output_i)
//       + 1 / combine(GATE, U_VAR_IDX, U_VALUE)
//   combine(t) = sum_k alpha^k * t[k] - z        (k < 6 = MAX_TUPLE)
//
// The node is accepted iff every input is canonical, no denominator is zero
// (the host `inv()` fails there) and sum == 0. Field arithmetic is exact
// (om31.cuh is the host basis), so the verdict is the host's verdict. One
// thread; it writes exactly one Verdict word (gpu_native.zig): 0 accepted,
// (0x0302 << 16) | detail rejected, followed by the caller's per-node tag (the
// job slab is not cleared between jobs: finish accepts the verdict only next
// to its own node's tag). Enqueue only, no sync, no readback.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

struct StwoRv64OuterLookupConstants {
  uint32_t relation;    // component_list.GATE_RELATION_ID
  uint32_t u_index;     // witness/trace.zig U_VAR_IDX
  uint32_t u_value[4];  // witness/trace.zig U_VALUE limbs
  uint32_t n_outputs;
  uint32_t n_claims;    // 11 (Plan.n_components)
  uint32_t tag;         // per-node tag echoed next to the verdict (stale-slab guard)
  uint32_t reserved[3];
};
static_assert(sizeof(StwoRv64OuterLookupConstants) == 48, "outer lookup constants ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kLookupSum = 0x0302u;
enum Detail : uint32_t {
  kNoncanonicalChallenge = 1,
  kNoncanonicalClaim = 2,
  kZeroDenominator = 3,
  kNoncanonicalOutput = 4,
  kNonzeroSum = 5,
  kBadShape = 6,
};
__device__ __forceinline__ uint32_t reduce(uint64_t x) {
  return uint32_t(x % q::kPrime);
}
__device__ __forceinline__ bool term(const OM31 powers[6], OM31 z, uint32_t relation,
                                     uint32_t address, const uint32_t limbs[4], OM31 &sum) {
  const uint32_t tuple[6] = {reduce(relation), reduce(address), limbs[0], limbs[1], limbs[2], limbs[3]};
  OM31 d = zero();
  for (uint32_t k = 0; k < 6; ++k) d = add(d, scale(powers[k], tuple[k]));
  d = sub(d, z);
  if (is_zero(d)) return false;
  sum = add(sum, inverse_nonzero(d));
  return true;
}
}  // namespace

__global__ void outer_lookup_sum_check(const uint32_t *claims, const uint32_t *z_alpha,
                                       const uint32_t *expected,
                                       StwoRv64OuterLookupConstants c, uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  const OM31 z = from_words(z_alpha), alpha = from_words(z_alpha + 8);
  if (!canonical(z) || !canonical(alpha)) detail = kNoncanonicalChallenge;
  OM31 powers[6];
  powers[0] = one();
  for (uint32_t k = 1; k < 6; ++k) powers[k] = mul(powers[k - 1], alpha);
  OM31 sum = zero();
  for (uint32_t i = 0; i < c.n_claims && !detail; ++i) {
    const OM31 claim = from_words(claims + 8 * i);
    if (!canonical(claim)) detail = kNoncanonicalClaim;
    sum = add(sum, claim);
  }
  for (uint32_t k = 0; k < 4 && !detail; ++k)
    if (c.u_value[k] >= q::kPrime) detail = kNoncanonicalOutput;
  for (uint32_t i = 0; i < c.n_outputs && !detail; ++i) {
    const uint32_t *limbs = expected + 4 * uint64_t(i);
    for (uint32_t k = 0; k < 4; ++k)
      if (limbs[k] >= q::kPrime) detail = kNoncanonicalOutput;
    if (!detail && !term(powers, z, c.relation, c.u_index + 1 + i, limbs, sum)) detail = kZeroDenominator;
  }
  if (!detail && !term(powers, z, c.relation, c.u_index, c.u_value, sum)) detail = kZeroDenominator;
  if (!detail && !is_zero(sum)) detail = kNonzeroSum;
  verdict[0] = detail ? ((kLookupSum << 16) | detail) : 0u;
  verdict[1] = c.tag;
}
}  // namespace stwo::cuda::rv64

// claims: n_claims x 8 words; z_alpha: 16 words; expected: n_outputs x 4 words
// (may be absent when n_outputs == 0); verdict: 1 word. All job-arena / slab
// memory of `context` (custody-checked), stream = the lane's exec stream.
extern "C" int stwo_rv64_outer_lookup_sum_check_v1_on(void *context, uint32_t lane,
                                                      const uint32_t *claims,
                                                      const uint32_t *z_alpha,
                                                      const uint32_t *expected,
                                                      const StwoRv64OuterLookupConstants *constants,
                                                      uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!constants || !constants->n_claims || constants->n_claims > 64 || constants->n_outputs > 4096)
    return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(claims, uint64_t(constants->n_claims) * 8, false) ||
      !custody.range(z_alpha, 16, false) ||
      (constants->n_outputs && !custody.range(expected, uint64_t(constants->n_outputs) * 4, false)) ||
      !custody.range(verdict, 2, true))
    return custody.status;
  outer_lookup_sum_check<<<1, 1, 0, custody.stream>>>(claims, z_alpha, expected, *constants, verdict);
  return int(cudaPeekAtLastError());
}

// Host-side ABI probe (no device): lets the Zig loader refuse a stale addon.
extern "C" uint32_t stwo_rv64_outer_checks_version(void) {
  return 1;
}

// ---------------------------------------------------------------------------
// node_oods_constraint (Check 0x0303): the composition polynomial at the OODS
// point from the sampled mask values equals the value the composition tree's
// samples reconstruct. Host reference: outer_job_prestage.zig assemble
// (om31 component.zig evaluateConstraintQuotientsAtPoint over every bound
// component, PointEvaluationAccumulator with the composition coefficient;
// proof_family.zig extractCompositionOodsEvalWithSplit). The per-class
// program (jobs/outer_encode_oods.zig, built by outer_job_prestage.zig
// oodsProgram) carries every part's AIR bytecode with mask reads resolved to
// PCS-image sample indices. One block: one thread per component part
// (parts are independent: each yields its Horner partial over its roots),
// then thread 0 folds the partials in order. Exact OM31 arithmetic.
struct StwoRv64OuterOodsIo {
  const uint32_t *desc;
  uint64_t desc_words;
  const uint32_t *samples;  // PCS image samples section, 8 words per sample
  uint64_t sample_words;
  const uint32_t *claims;      // 11 claims x 8 words (om31 outer: header claims == 11)
  const uint32_t *challenges;  // z | alpha | coefficient (24 words)
  const uint32_t *point;       // native_pcs OODS field (33 words): x[8] | y[8] | base x[8] y[8] | status
  uint32_t *scratch;           // header scratch words + 9 per part
  uint64_t scratch_words;
  uint32_t *verdict;  // 1 word
  uint32_t *diag;     // 16 words [evaluated | extracted] or null
};
static_assert(sizeof(StwoRv64OuterOodsIo) == 88, "outer OODS Io ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kOodsConstraint = 0x0303u;
constexpr uint32_t kOodsThreads = 128;
enum : uint32_t { oMagic = 0, oVersion = 1, oWords = 2, oParts = 3, oGlobalLog = 4, oCompositionLog = 5, oSplit = 6,
                  oCompositionSample = 7, oSamples = 8, oScratch = 9, oClaims = 10, oHeader = 16 };
enum : uint32_t { pComponent = 0, pTraceLog = 1, pClaim = 2, pParamsAt = 3, pNParams = 4, pBaseAt = 5, pNBase = 6,
                  pExtAt = 7, pNExt = 8, pRootsAt = 9, pNRoots = 10, pRegsAt = 11, pMaxBase = 12, pMaxExt = 13,
                  pInitial = 14, pHalfStep = 16, pCosetLog = 18, pClaimScale = 19, pWords = 24 };
enum : uint32_t { oDescriptor = 1, oNoncanonical = 2, oZeroInverse = 3, oMismatch = 4, oPoint = 5 };
constexpr uint32_t kNoSample = 0xffffffffu;

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
__device__ __forceinline__ Pt mpoint(uint32_t x, uint32_t y) {
  return {base(x), base(y)};
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
// om31.zig fromPartialEvals.
__device__ OM31 from_partial_evals(const OM31 e[8]) {
  const q::QM31 l0 = qpe(e[0].c0, e[1].c0, e[2].c0, e[3].c0), l1 = qpe(e[0].c1, e[1].c1, e[2].c1, e[3].c1);
  const q::QM31 u0 = qpe(e[4].c0, e[5].c0, e[6].c0, e[7].c0), u1 = qpe(e[4].c1, e[5].c1, e[6].c1, e[7].c1);
  return {q::add(l0, mul_u(u1)), q::add(l1, u0)};
}
__device__ __forceinline__ OM31 embed4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  return {{{a, b}, {c, d}}, q::zero()};
}
__device__ __forceinline__ OM31 vbasis() {
  return {q::zero(), q::one()};
}
__device__ __forceinline__ void oods_refuse(uint32_t *fail, uint32_t detail) {
  atomicMin(fail, detail);
}

// One component part: its Horner partial sum over its roots (times the
// component's inverse coset vanishing at the doubled point).
__device__ void oods_part(const StwoRv64OuterOodsIo &io, const uint32_t *row, Pt point, OM31 z, OM31 alpha,
                          OM31 coeff, uint32_t *out, uint32_t *fail) {
  const uint32_t *d = io.desc;
  const uint32_t n_samples = uint32_t(io.sample_words / 8);
  Pt local = point;
  for (uint32_t i = row[pTraceLog]; i < d[oGlobalLog]; ++i) local = padd(local, local);
  // core/constraints.zig cosetVanishing: p - initial + half_step, then doubleX.
  Pt p = padd(local, mpoint(row[pInitial], row[pInitial + 1] ? q::kPrime - row[pInitial + 1] : 0u));
  p = padd(p, mpoint(row[pHalfStep], row[pHalfStep + 1]));
  OM31 x = p.x;
  for (uint32_t i = 1; i < row[pCosetLog]; ++i) x = sub(add(mul(x, x), mul(x, x)), one());
  if (is_zero(x)) return oods_refuse(fail, oZeroInverse);
  const OM31 inv = inverse_nonzero(x);
  const OM31 claim = from_words(io.claims + 8 * row[pClaim]);
  OM31 *regs = reinterpret_cast<OM31 *>(io.scratch + row[pRegsAt]);
  const uint32_t max_base = row[pMaxBase], max_ext = row[pMaxExt];
  OM31 *ext = regs + max_base;
  const uint32_t *bi = d + row[pBaseAt];
  for (uint32_t k = 0; k < row[pNBase]; ++k, bi += 6) {
    const uint32_t op = bi[0], dst = bi[1], a = bi[2], b = bi[3];
    if (dst >= max_base) return oods_refuse(fail, oDescriptor);
    OM31 v;
    switch (op) {
      case 0:
      case 1:  // trace_col / preprocessed_col
        if (bi[4] >= n_samples || (bi[5] != kNoSample && bi[5] >= n_samples)) return oods_refuse(fail, oDescriptor);
        v = from_words(io.samples + 8ull * bi[4]);
        if (bi[5] != kNoSample) v = add(v, mul(vbasis(), from_words(io.samples + 8ull * bi[5])));
        break;
      case 3:  // constant
        if (a >= q::kPrime) return oods_refuse(fail, oDescriptor);
        v = base(a);
        break;
      case 4: case 5: case 6:
        if (a >= max_base || b >= max_base) return oods_refuse(fail, oDescriptor);
        v = op == 4 ? add(regs[a], regs[b]) : op == 5 ? sub(regs[a], regs[b]) : mul(regs[a], regs[b]);
        break;
      case 7:
        if (a >= max_base) return oods_refuse(fail, oDescriptor);
        v = negate(regs[a]);
        break;
      case 8:
        if (a >= max_base) return oods_refuse(fail, oDescriptor);
        if (is_zero(regs[a])) return oods_refuse(fail, oZeroInverse);
        v = inverse_nonzero(regs[a]);
        break;
      default:  // base params are refused at warm
        return oods_refuse(fail, oDescriptor);
    }
    regs[dst] = v;
  }
  const uint32_t *ei = d + row[pExtAt];
  for (uint32_t k = 0; k < row[pNExt]; ++k, ei += 6) {
    const uint32_t op = ei[0], dst = ei[1], a = ei[2], b = ei[3], c = ei[4], e = ei[5];
    if (dst >= max_ext) return oods_refuse(fail, oDescriptor);
    OM31 v;
    switch (op) {
      case 0: {  // secure_col: pack4
        if (a >= max_base || b >= max_base || c >= max_base || e >= max_base) return oods_refuse(fail, oDescriptor);
        const OM31 parts[8] = {regs[a], regs[b], regs[c], regs[e], zero(), zero(), zero(), zero()};
        v = from_partial_evals(parts);
        break;
      }
      case 1: {  // param
        if (a >= row[pNParams]) return oods_refuse(fail, oDescriptor);
        const uint32_t *s = d + row[pParamsAt] + 6 * a;
        switch (s[0]) {
          case 0: v = embed4(s[1], s[2], s[3], s[4]); break;
          case 1: v = z; break;
          case 2: v = power(alpha, s[5]); break;
          case 3: v = scale(power(alpha, s[5]), s[1]); break;
          case 4: v = scale(claim, row[pClaimScale]); break;
          default: return oods_refuse(fail, oDescriptor);
        }
        break;
      }
      case 2:  // constant
        v = embed4(a, b, c, e);
        break;
      case 3: case 4: case 5:
        if (a >= max_ext || b >= max_ext) return oods_refuse(fail, oDescriptor);
        v = op == 3 ? add(ext[a], ext[b]) : op == 4 ? sub(ext[a], ext[b]) : mul(ext[a], ext[b]);
        break;
      case 6:
        if (a >= max_ext) return oods_refuse(fail, oDescriptor);
        v = negate(ext[a]);
        break;
      default:
        return oods_refuse(fail, oDescriptor);
    }
    ext[dst] = v;
  }
  OM31 h = zero();
  const uint32_t *roots = d + row[pRootsAt];
  for (uint32_t k = 0; k < row[pNRoots]; ++k) {
    if (roots[k] >= max_ext) return oods_refuse(fail, oDescriptor);
    h = add(mul(h, coeff), mul(ext[roots[k]], inv));
  }
  store8(out, h);
  out[8] = 1;
}

__global__ void __launch_bounds__(kOodsThreads) outer_oods_check(StwoRv64OuterOodsIo io) {
  __shared__ uint32_t fail;
  const uint32_t tid = threadIdx.x;
  const uint32_t *d = io.desc;
  if (tid == 0) fail = 0xffffffffu;
  __syncthreads();
  const bool head = d[oMagic] == 0x53444f4fu && d[oVersion] == 1 && d[oWords] == io.desc_words && d[oParts] &&
                    oHeader + uint64_t(d[oParts]) * pWords <= io.desc_words &&
                    uint64_t(d[oSamples]) * 8 <= io.sample_words &&
                    uint64_t(d[oScratch]) + 9ull * d[oParts] <= io.scratch_words && d[oSplit] == 1 && d[oClaims] == 11 &&
                    d[oCompositionLog] > d[oSplit] && uint64_t(d[oCompositionSample]) + 16 <= d[oSamples];
  if (!head) {
    if (tid == 0) io.verdict[0] = (kOodsConstraint << 16) | oDescriptor;
    return;
  }
  const Pt point{from_words(io.point), from_words(io.point + 8)};
  const OM31 z = from_words(io.challenges), alpha = from_words(io.challenges + 8), coeff = from_words(io.challenges + 16);
  if (tid == 0) {
    bool ok = canonical(point.x) && canonical(point.y) && canonical(z) && canonical(alpha) && canonical(coeff);
    for (uint32_t i = 0; i < d[oClaims] && ok; ++i) ok = canonical(from_words(io.claims + 8 * i));
    if (!ok) oods_refuse(&fail, oNoncanonical);
    // The device point build's status word (host finish: InvalidOuterOodsPoint).
    if (io.point[32]) oods_refuse(&fail, oPoint);
  }
  uint32_t *partials = io.scratch + d[oScratch];
  for (uint32_t p = tid; p < d[oParts]; p += kOodsThreads) {
    const uint32_t *row = d + oHeader + p * pWords;
    partials[9 * p + 8] = 0;
    if (row[pClaim] >= d[oClaims] || row[pTraceLog] > d[oGlobalLog] ||
        uint64_t(row[pRegsAt]) + 8ull * (uint64_t(row[pMaxBase]) + row[pMaxExt]) > d[oScratch]) {
      oods_refuse(&fail, oDescriptor);
      continue;
    }
    oods_part(io, row, point, z, alpha, coeff, partials + 9 * p, &fail);
  }
  __syncthreads();
  if (tid) return;
  // In order: acc = acc * coeff^n_roots(p) + partial(p).
  OM31 acc = zero();
  for (uint32_t p = 0; p < d[oParts] && fail == 0xffffffffu; ++p) {
    const uint32_t *row = d + oHeader + p * pWords;
    if (!partials[9 * p + 8]) {
      oods_refuse(&fail, oDescriptor);
      break;
    }
    acc = add(mul(acc, power(coeff, row[pNRoots])), from_words(partials + 9 * p));
  }
  // Composition samples: chunk c coordinates k at composition column c*8+k.
  OM31 chunk[2];
  for (uint32_t c = 0; c < 2; ++c) {
    OM31 e[8];
    for (uint32_t k = 0; k < 8; ++k) e[k] = from_words(io.samples + 8ull * (d[oCompositionSample] + c * 8 + k));
    chunk[c] = from_partial_evals(e);
  }
  Pt f = point;
  const uint32_t parent_log = d[oCompositionLog] - d[oSplit] + 1;
  for (uint32_t i = 0; i + 2 < parent_log; ++i) f = padd(f, f);
  const OM31 extracted = add(chunk[0], mul(f.x, chunk[1]));
  if (io.diag && fail == 0xffffffffu) {
    store8(io.diag, acc);
    store8(io.diag + 8, extracted);
  }
  uint32_t word = 0;
  if (fail != 0xffffffffu) word = (kOodsConstraint << 16) | fail;
  else {
    bool eq = true;
    for (uint32_t c = 0; c < 8; ++c) eq = eq && coordinate(acc, c) == coordinate(extracted, c);
    if (!eq) word = (kOodsConstraint << 16) | oMismatch;
  }
  io.verdict[0] = word;
}
}  // namespace
}  // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_outer_oods_check_v1_on(void *context, uint32_t lane, const StwoRv64OuterOodsIo *io) {
  using namespace stwo::cuda::rv64;
  if (!io || !io->desc || io->desc_words < 16 || !io->samples || !io->sample_words || !io->claims || !io->challenges ||
      !io->point || !io->scratch || !io->scratch_words || !io->verdict)
    return int(cudaErrorInvalidValue);
  RangeCustody<9> custody(context, lane);
  const bool ok = custody.range(io->desc, io->desc_words, false) && custody.range(io->samples, io->sample_words, false) &&
                  custody.range(io->claims, 88, false) && custody.range(io->challenges, 24, false) &&
                  custody.range(io->point, 33, false) && custody.range(io->scratch, io->scratch_words, true) &&
                  custody.range(io->verdict, 1, true) && (!io->diag || custody.range(io->diag, 16, true));
  if (!ok) return custody.status ? custody.status : int(cudaErrorInvalidValue);
  outer_oods_check<<<1, kOodsThreads, 0, custody.stream>>>(*io);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_outer_oods_check_version(void) {
  return 1;
}
