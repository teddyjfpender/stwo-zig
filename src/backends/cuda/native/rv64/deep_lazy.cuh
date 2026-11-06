#ifndef STWO_CUDA_RV64_DEEP_LAZY_CUH
#define STWO_CUDA_RV64_DEEP_LAZY_CUH
#include "om31.cuh"
// Lazy-reduction M31/QM31 helpers for the DEEP/OODS kernels (T3, M8).
// Every helper returns the canonical representative, so results are
// bit-identical to the reference q::/OM31 arithmetic for canonical inputs:
// the field value is unique and its canonical encoding is unique.
// Products of canonical words (or of P - canonical, which is <= P) are below
// 2^62; four of them sum below 2^64 and are reduced once instead of per
// product (one 64-bit fold, one 32-bit fold, one conditional subtraction).
namespace stwo::cuda::rv64::lazy {
constexpr uint32_t P = q::kPrime;
// STWO_RV64_DEEP_LAZY_FOLD=1 folds via 2^32 = 2 (mod P): x = 2 hi + lo, one
// IMAD.WIDE on the FMA pipe instead of the 64-bit shift/mask/add ALU chain.
// [M] A/B (deep_t3_parity_bench, 5090, 7 reps, median): deep_combine 2^22 x
// 68 groups 4.46 ms (ALU fold, 0) vs 4.68 ms (FMA fold, 1); sample 2^22 x 72
// 0.912 vs 0.919 ms. The products already load the FMA pipe; keep 0.
#ifndef STWO_RV64_DEEP_LAZY_FOLD
#define STWO_RV64_DEEP_LAZY_FOLD 0
#endif
__device__ __forceinline__ uint32_t fold_small(uint64_t s) {
  // s < 2^36: (s & P) + (s >> 31) < P + 33; min() is the conditional subtract.
  const uint32_t u = (uint32_t(s) & P) + uint32_t(s >> 31);
  return min(u, u - P);
}
__device__ __forceinline__ uint32_t reduce64(uint64_t x) {
#if STWO_RV64_DEEP_LAZY_FOLD
  return fold_small(uint64_t(uint32_t(x >> 32)) * 2u + uint32_t(x)); // < 3 2^32
#else
  const uint64_t t = (x & P) + (x >> 31);                 // < 2^31 + 2^33
  const uint32_t u = uint32_t(t & P) + uint32_t(t >> 31); // < P + 9
  return u >= P ? u - P : u;
#endif
}
// Sum of two values below 2^64 each, reduced.
__device__ __forceinline__ uint32_t reduce64x2(uint64_t a, uint64_t b) {
#if STWO_RV64_DEEP_LAZY_FOLD
  return fold_small(uint64_t(uint32_t(a >> 32)) * 2u + uint32_t(a) +
                    uint64_t(uint32_t(b >> 32)) * 2u + uint32_t(b)); // < 6 2^32
#else
  const uint64_t t = (a & P) + (a >> 31) + (b & P) + (b >> 31); // < 2^35
  const uint32_t u = uint32_t(t & P) + uint32_t(t >> 31);       // < P + 17
  return u >= P ? u - P : u;
#endif
}
__device__ __forceinline__ uint64_t mac(uint64_t acc, uint32_t a, uint32_t b) {
  return acc + uint64_t(a) * b;
}
// Right operand of a QM31 product, prepared once and reused across products:
// (b2 + b3 i) is pre-multiplied by R = 2 + i, negations are P - b (<= P).
struct QB {
  uint32_t b0, b1, b2, b3, nb1, nb3, r0, r1, nr1;
};
__device__ __forceinline__ QB prepare(q::QM31 b) {
  QB o;
  o.b0 = b.a.a;
  o.b1 = b.a.b;
  o.b2 = b.b.a;
  o.b3 = b.b.b;
  o.nb1 = P - o.b1;
  o.nb3 = P - o.b3;
  o.r0 = q::sub(q::add(o.b2, o.b2), o.b3);
  o.r1 = q::add(o.b2, q::add(o.b3, o.b3));
  o.nr1 = P - o.r1;
  return o;
}
// a * b over QM31 = CM31[u]/(u^2 - 2 - i):
//   c0 + c1 i = A0 B0 + A1 (R B1),  c2 + c3 i = A0 B1 + A1 B0.
// Each coordinate is four nonnegative products (< 2^64), reduced once.
struct QSums {
  uint64_t s0, s1, s2, s3;
};
__device__ __forceinline__ QSums qsums(q::QM31 x, const QB &y) {
  return {mac(mac(mac(uint64_t(x.a.a) * y.b0, x.a.b, y.nb1), x.b.a, y.r0),
              x.b.b, y.nr1),
          mac(mac(mac(uint64_t(x.a.a) * y.b1, x.a.b, y.b0), x.b.a, y.r1),
              x.b.b, y.r0),
          mac(mac(mac(uint64_t(x.a.a) * y.b2, x.a.b, y.nb3), x.b.a, y.b0),
              x.b.b, y.nb1),
          mac(mac(mac(uint64_t(x.a.a) * y.b3, x.a.b, y.b2), x.b.a, y.b1),
              x.b.b, y.b0)};
}
__device__ __forceinline__ q::QM31 qmul(q::QM31 x, const QB &y) {
  const QSums s = qsums(x, y);
  return {{reduce64(s.s0), reduce64(s.s1)}, {reduce64(s.s2), reduce64(s.s3)}};
}
// x * y + z * w with one reduction per coordinate.
__device__ __forceinline__ q::QM31 qmul_add(q::QM31 x, const QB &y, q::QM31 z,
                                            const QB &w) {
  const QSums s = qsums(x, y), t = qsums(z, w);
  return {{reduce64x2(s.s0, t.s0), reduce64x2(s.s1, t.s1)},
          {reduce64x2(s.s2, t.s2), reduce64x2(s.s3, t.s3)}};
}
} // namespace stwo::cuda::rv64::lazy
#endif
