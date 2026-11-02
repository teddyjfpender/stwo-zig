// Host tests for the candidate curve, field and sponge glue (our code).
//
// Built by `build.py --host --tests` with CANDIDATE_ARITH, CANDIDATE_BN and
// CANDIDATE_BLS on the evmone/blst units it links and portable (no-asm) blst,
// so every hook in patches 0020/0021 is live; services are the software
// emulation in glue/host_services.cpp. Each hooked path is compared with an
// independent intx reference written here:
//   BN254: ecMul/ecAdd (evmone entry points) vs naive affine double-and-add,
//          Fq2 multiply/sqr vs the textbook formula;
//   BLS12-381: blst Fp/Fp2 products vs intx Montgomery arithmetic, pairing
//          bilinearity e([a]G1, G2) = e(G1, [a]G2), evmone's KZG vectors;
//   Keccak: the sponge service vs the admitted-path ethash_keccak256 for
//          every length 0..600 at all 8 alignments, and split absorb calls.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <random>
#include <tuple>

#include <blst.h>
#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/keccak.h>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/pairing/bn254/fields.hpp>
#include <evmone_precompiles/sha256.hpp>
#include <intx/intx.hpp>

#include "candidate_curves.hpp"

extern "C" uint64_t stwo_host_curve_calls[256];  // glue/host_services.cpp

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept {
    std::fprintf(stderr, "guest abort: %s\n", why);
    std::abort();
}

namespace {
using intx::uint256;
using u384 = intx::uint<384>;
int failures = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            if (++failures > 20) std::exit(1);                                   \
        }                                                                        \
    } while (0)

std::mt19937_64 rng(0x5eed'c0ffee);
template <typename U>
U rnd() {
    U v;
    for (unsigned i = 0; i < U::num_words; ++i) v[i] = rng();
    return v;
}

// ------------------------------------------------------------ BN254 reference
const uint256 P = evmone::crypto::bn254::Curve::FIELD_PRIME;
const uint256 N = evmone::crypto::bn254::Curve::ORDER;
uint256 mulm(const uint256& a, const uint256& b) { return intx::mulmod(a, b, P); }
uint256 addm(const uint256& a, const uint256& b) { return intx::addmod(a, b, P); }
uint256 subm(const uint256& a, const uint256& b) { return a >= b ? a - b : P - (b - a); }
uint256 invm(uint256 a) {
    uint256 r = 1, e = P - 2;
    while (e != 0) {
        if (e & 1) r = mulm(r, a);
        a = mulm(a, a);
        e >>= 1;
    }
    return r;
}
struct Ref {
    uint256 x, y;
    bool inf = true;
};
Ref radd(const Ref& p, const Ref& q) {
    if (p.inf) return q;
    if (q.inf) return p;
    uint256 l;
    if (p.x == q.x) {
        if (p.y != q.y || p.y == 0) return {};
        l = mulm(mulm(3, mulm(p.x, p.x)), invm(addm(p.y, p.y)));
    } else {
        l = mulm(subm(q.y, p.y), invm(subm(q.x, p.x)));
    }
    Ref r;
    r.inf = false;
    r.x = subm(subm(mulm(l, l), p.x), q.x);
    r.y = subm(mulm(l, subm(p.x, r.x)), p.y);
    return r;
}
Ref rmul(const Ref& p, const uint256& k) {
    Ref acc;
    for (int i = 255; i >= 0; --i) {
        acc = radd(acc, acc);
        if ((k >> i) & 1) acc = radd(acc, p);
    }
    return acc;
}

void test_bn254() {
    using namespace evmone::crypto::bn254;
    const Ref g{1, 2, false};
    const uint256 edge[] = {0, 1, 2, 3, 15, 16, 17, N - 1, N, N + 1, 2 * N, 5 * N + 7, ~uint256{0}, uint256{1} << 255};
    int cases = 0;
    for (int t = 0; t < 40; ++t) {
        const Ref p = rmul(g, rnd<uint256>() % N);
        const AffinePoint ep{Fq{p.x}, Fq{p.y}};
        for (int s = 0; s < 18; ++s) {
            const uint256 k = s < 14 ? edge[s] : rnd<uint256>() >> (s * 13 % 200);
            const Ref want = rmul(p, k);
            const AffinePoint got = mul(ep, k);
            CHECK((got == 0) == want.inf);
            if (!want.inf) CHECK(got.x.value() == want.x && got.y.value() == want.y);
            ++cases;
        }
        const Ref q = rmul(g, rnd<uint256>() % N);
        const AffinePoint eq{Fq{q.x}, Fq{q.y}};
        const Ref negp{p.x, P - p.y, false};
        const AffinePoint enegp{Fq{negp.x}, Fq{negp.y}};
        for (auto [a, b, ea, eb] : {std::tuple{p, q, ep, eq}, std::tuple{p, p, ep, ep}, std::tuple{p, negp, ep, enegp},
                                    std::tuple{p, Ref{}, ep, AffinePoint{}}, std::tuple{Ref{}, q, AffinePoint{}, eq}}) {
            const Ref want = radd(a, b);
            const AffinePoint got = add(ea, eb);
            CHECK((got == 0) == want.inf);
            if (!want.inf) CHECK(got.x.value() == want.x && got.y.value() == want.y);
            ++cases;
        }
    }
    for (int t = 0; t < 2000; ++t) {
        const uint256 a0 = rnd<uint256>() % P, a1 = rnd<uint256>() % P, b0 = rnd<uint256>() % P, b1 = rnd<uint256>() % P;
        const Fq2 a({Fq{a0}, Fq{a1}}), b({Fq{b0}, Fq{b1}});
        const Fq2 m = multiply(a, b), s = sqr(a);
        CHECK(m.coeffs[0].value() == subm(mulm(a0, b0), mulm(a1, b1)));
        CHECK(m.coeffs[1].value() == addm(mulm(a0, b1), mulm(a1, b0)));
        CHECK(s.coeffs[0].value() == subm(mulm(a0, a0), mulm(a1, a1)));
        CHECK(s.coeffs[1].value() == addm(mulm(a0, a1), mulm(a1, a0)));
        cases += 2;
    }
    // The hooks are live: every BN254 service was used.
    CHECK(stwo_host_curve_calls[0x00] && stwo_host_curve_calls[0x01] && stwo_host_curve_calls[0x02]);
    std::printf("bn254: %d cases (add %llu, double %llu, fp2_mul %llu service calls)\n", cases,
                (unsigned long long)stwo_host_curve_calls[0x00], (unsigned long long)stwo_host_curve_calls[0x01],
                (unsigned long long)stwo_host_curve_calls[0x02]);
}

// ------------------------------------------------------------ BLS12-381 reference
const u384 Q = intx::from_string<u384>(
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
u384 qmul(const u384& a, const u384& b) { return static_cast<u384>(intx::umul(a, b) % intx::uint<768>{Q}); }
u384 qadd(const u384& a, const u384& b) { return static_cast<u384>((intx::uint<448>{a} + b) % Q); }
u384 qsub(const u384& a, const u384& b) { return a >= b ? a - b : Q - (b - a); }
blst_fp to_fp(const u384& v) {
    uint64_t w[6];
    for (int i = 0; i < 6; ++i) w[i] = v[i];
    blst_fp r;
    blst_fp_from_uint64(&r, w);  // plain -> Montgomery (itself a hooked product)
    return r;
}
u384 from_fp(const blst_fp& f) {
    uint64_t w[6];
    blst_uint64_from_fp(w, &f);
    u384 v;
    for (int i = 0; i < 6; ++i) v[i] = w[i];
    return v;
}

void test_bls() {
    int cases = 0;
    for (int t = 0; t < 2000; ++t) {
        const u384 a0 = rnd<u384>() % Q, a1 = rnd<u384>() % Q, b0 = rnd<u384>() % Q, b1 = rnd<u384>() % Q;
        blst_fp fa = to_fp(a0), fb = to_fp(b0), fr;
        blst_fp_mul(&fr, &fa, &fb);
        CHECK(from_fp(fr) == qmul(a0, b0));
        blst_fp_sqr(&fr, &fa);
        CHECK(from_fp(fr) == qmul(a0, a0));
        blst_fp2 x, y, z;
        x.fp[0] = fa;
        x.fp[1] = to_fp(a1);
        y.fp[0] = fb;
        y.fp[1] = to_fp(b1);
        blst_fp2_mul(&z, &x, &y);
        CHECK(from_fp(z.fp[0]) == qsub(qmul(a0, b0), qmul(a1, b1)));
        CHECK(from_fp(z.fp[1]) == qadd(qmul(a0, b1), qmul(a1, b0)));
        blst_fp2_sqr(&z, &x);
        CHECK(from_fp(z.fp[0]) == qsub(qmul(a0, a0), qmul(a1, a1)));
        CHECK(from_fp(z.fp[1]) == qadd(qmul(a0, a1), qmul(a1, a0)));
        cases += 4;
    }
    // Pairing bilinearity through every hooked tower product.
    for (int t = 0; t < 3; ++t) {
        uint8_t k[32];
        for (auto& b : k) b = uint8_t(rng());
        blst_p1 p1;
        blst_p2 p2;
        blst_p1_mult(&p1, blst_p1_generator(), k, 255);
        blst_p2_mult(&p2, blst_p2_generator(), k, 255);
        blst_p1_affine a1, g1;
        blst_p2_affine a2, g2;
        blst_p1_to_affine(&a1, &p1);
        blst_p2_to_affine(&a2, &p2);
        blst_p1_to_affine(&g1, blst_p1_generator());
        blst_p2_to_affine(&g2, blst_p2_generator());
        blst_fp12 l, r, base;
        blst_miller_loop(&l, &g2, &a1);
        blst_final_exp(&l, &l);
        blst_miller_loop(&r, &a2, &g1);
        blst_final_exp(&r, &r);
        blst_miller_loop(&base, &g2, &g1);
        blst_final_exp(&base, &base);
        CHECK(blst_fp12_is_equal(&l, &r));
        CHECK(!blst_fp12_is_equal(&l, &base));
        cases += 2;
    }
    // evmone's KZG unit vectors (precompiles_kzg_test.cpp), recomputed here.
    using evmone::crypto::kzg_verify_proof;
    const std::byte zero32[32]{};
    std::byte inf48[48]{};
    inf48[0] = std::byte{0xC0};
    auto vhash = [](const std::byte* in, size_t n) {
        std::array<std::byte, 32> h{};
        evmone::crypto::sha256(h.data(), in, n);
        h[0] = std::byte{0x01};
        return h;
    };
    CHECK(!kzg_verify_proof(zero32, zero32, zero32, inf48, inf48));
    std::byte z[32]{};
    z[13] = std::byte{17};
    CHECK(kzg_verify_proof(vhash(inf48, 48).data(), z, zero32, inf48, inf48));
    const auto gx = intx::from_string<u384>(
        "0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB");
    std::byte c[48]{}, y1[32]{};
    y1[31] = std::byte{1};
    intx::be::unsafe::store(reinterpret_cast<uint8_t*>(c), gx);
    c[0] |= std::byte{0x80};
    CHECK(kzg_verify_proof(vhash(c, 48).data(), z, y1, c, inf48));  // f(x) = 1
    std::byte y2[32]{};
    y2[31] = std::byte{2};
    CHECK(!kzg_verify_proof(vhash(c, 48).data(), z, y2, c, inf48));  // wrong evaluation
    c[0] |= std::byte{0xA0};                                          // C = -G1, forces a final doubling
    CHECK(!kzg_verify_proof(vhash(c, 48).data(), zero32, y1, c, inf48));
    cases += 5;
    CHECK(stwo_host_curve_calls[0x12] && stwo_host_curve_calls[0x21]);
    std::printf("bls12-381: %d cases (fp2_mul %llu, arith384_mont %llu service calls)\n", cases,
                (unsigned long long)stwo_host_curve_calls[0x12], (unsigned long long)stwo_host_curve_calls[0x21]);
}

// ------------------------------------------------------------ Keccak sponge
void test_keccak() {
    alignas(8) uint8_t buf[700 + 8];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = uint8_t(i * 29 + 11);
    int cases = 0;
    for (size_t off = 0; off < 8; ++off)
        for (size_t n = 0; n <= 600; ++n) {
            const auto want = ethash_keccak256(buf + off, n);  // admitted path (no CANDIDATE_KECCAK here)
            alignas(8) uint64_t st[25];
            stwo::cand_keccak256(st, buf + off, n);
            CHECK(std::memcmp(st, want.word64s, 32) == 0);
            ++cases;
        }
    // Two full blocks, then the tail with padding, in separate calls.
    alignas(8) uint64_t st[25];
    alignas(8) uint64_t pk[4] = {stwo::ptr(st), stwo::ptr(buf + 3), 272, stwo::kSpongeFresh};
    stwo::ecall(stwo::kCandKeccakSponge, pk);
    alignas(8) uint64_t pk2[4] = {stwo::ptr(st), stwo::ptr(buf + 3 + 272), 100, stwo::kSpongeFinalize};
    stwo::ecall(stwo::kCandKeccakSponge, pk2);
    CHECK(std::memcmp(st, ethash_keccak256(buf + 3, 372).word64s, 32) == 0);
    CHECK(stwo_host_curve_calls[0x30] == uint64_t(cases) + 2);
    std::printf("keccak sponge: %d cases\n", cases + 1);
}
}  // namespace

int main() {
    test_bn254();
    test_bls();
    test_keccak();
    if (failures) {
        std::printf("%d failures\n", failures);
        return 1;
    }
    std::printf("curves_test: all passed\n");
    return 0;
}
