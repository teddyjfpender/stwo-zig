#ifndef STWO_CUDA_RV64_OM31_CUH
#define STWO_CUDA_RV64_OM31_CUH

#include "oods/field.cuh"

// Same basis as core/fields/om31.zig: i^2=-1, u^2=2+i, v^2=u.
// Coordinate order: 1,i,u,iu,v,iv,uv,iuv. No reinterpretation as QM31 pairs
// from different extension towers is allowed.
namespace stwo::cuda::rv64 {
namespace q = stwo::cuda::oods;
struct OM31 {
    q::QM31 c0, c1;
};
static_assert(sizeof(OM31) == 32 && alignof(OM31) == 4, "OM31 ABI");
__host__ __device__ __forceinline__ OM31 zero() {
    return {q::zero(), q::zero()};
}
__host__ __device__ __forceinline__ OM31 one() {
    return {q::one(), q::zero()};
}
__host__ __device__ __forceinline__ OM31 base(uint32_t a) {
    return {{{a, 0}, {0, 0}}, q::zero()};
}
__host__ __device__ __forceinline__ OM31 add(OM31 a, OM31 b) {
    return {q::add(a.c0, b.c0), q::add(a.c1, b.c1)};
}
__host__ __device__ __forceinline__ OM31 sub(OM31 a, OM31 b) {
    return {q::sub(a.c0, b.c0), q::sub(a.c1, b.c1)};
}
__host__ __device__ __forceinline__ q::QM31 mul_u(q::QM31 a) {
    return {q::mul(q::kExtensionR, a.b), a.a};
}
__host__ __device__ __forceinline__ OM31 mul(OM31 a, OM31 b) {
    const auto ac = q::mul(a.c0, b.c0), bd = q::mul(a.c1, b.c1);
    const auto cross = q::sub(q::sub(q::mul(q::add(a.c0, a.c1), q::add(b.c0, b.c1)), ac), bd);
    return {q::add(ac, mul_u(bd)), cross};
}
__host__ __device__ __forceinline__ OM31 scale(OM31 a, uint32_t b) {
    return {q::mul(b, a.c0), q::mul(b, a.c1)};
}
__host__ __device__ __forceinline__ OM31 fold(OM31 a, OM31 b, OM31 x) {
    return add(a, mul(sub(b, a), x));
}
__host__ __device__ __forceinline__ bool is_zero(OM31 a) {
    return !(a.c0.a.a | a.c0.a.b | a.c0.b.a | a.c0.b.b | a.c1.a.a | a.c1.a.b | a.c1.b.a |
             a.c1.b.b);
}
__host__ __device__ __forceinline__ uint32_t coordinate(OM31 a, uint32_t c) {
    const uint32_t values[8] = {a.c0.a.a, a.c0.a.b, a.c0.b.a, a.c0.b.b,
                                a.c1.a.a, a.c1.a.b, a.c1.b.a, a.c1.b.b};
    return values[c];
}
__host__ __device__ __forceinline__ OM31 from_words(const uint32_t* a) {
    return {{{a[0], a[1]}, {a[2], a[3]}}, {{a[4], a[5]}, {a[6], a[7]}}};
}
__host__ __device__ __forceinline__ bool canonical(OM31 a) {
    bool ok = true;
    for (uint32_t c = 0; c < 8; ++c) ok = ok && coordinate(a, c) < q::kPrime;
    return ok;
}
__host__ __device__ __forceinline__ OM31 load(const uint32_t* p, uint64_t stride, uint64_t i) {
    return {{{p[i], p[stride + i]}, {p[2 * stride + i], p[3 * stride + i]}},
            {{p[4 * stride + i], p[5 * stride + i]}, {p[6 * stride + i], p[7 * stride + i]}}};
}
__host__ __device__ __forceinline__ void store(uint32_t* p, uint64_t stride, uint64_t i,
                                               OM31 a) {
    for (uint32_t c = 0; c < 8; ++c) p[c * stride + i] = coordinate(a, c);
}
struct Fraction {
    OM31 n, d;
};
__host__ __device__ __forceinline__ Fraction combine(Fraction a, Fraction b) {
    return {add(mul(a.n, b.d), mul(b.n, a.d)), mul(a.d, b.d)};
}
__host__ __device__ __forceinline__ Fraction combine_base(uint32_t an, OM31 ad, uint32_t bn,
                                                          OM31 bd) {
    return {add(scale(bd, an), scale(ad, bn)), mul(ad, bd)};
}
struct Pair {
    OM31 at0, at2;
};
// This is the native evalLogupSumRange polynomial, before fixed-variable
// correction and interpolation. t indexes adjacent children in two halves.
__host__ __device__ __forceinline__ Pair sum_term(Fraction a, Fraction b, Fraction c,
                                                  Fraction d, OM31 eq, OM31 lambda) {
    const Fraction at0 = combine(a, b);
    const Fraction at2 = combine({sub(add(c.n, c.n), a.n), sub(add(c.d, c.d), a.d)},
                                 {sub(add(d.n, d.n), b.n), sub(add(d.d, d.d), b.d)});
    return {mul(eq, add(at0.n, mul(lambda, at0.d))), mul(eq, add(at2.n, mul(lambda, at2.d)))};
}
__host__ __device__ __forceinline__ Pair sum_term_base(uint32_t an, OM31 ad, uint32_t bn,
                                                       OM31 bd, uint32_t cn, OM31 cd,
                                                       uint32_t dn, OM31 dd, OM31 eq,
                                                       OM31 lambda) {
    const auto a = combine_base(an, ad, bn, bd);
    const auto b = combine_base(q::sub(q::add(cn, cn), an), sub(add(cd, cd), ad),
                                q::sub(q::add(dn, dn), bn), sub(add(dd, dd), bd));
    return {mul(eq, add(a.n, mul(lambda, a.d))), mul(eq, add(b.n, mul(lambda, b.d)))};
}
}  // namespace stwo::cuda::rv64
#endif
