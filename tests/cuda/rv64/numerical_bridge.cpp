#include "rv64/om31.cuh"
using namespace stwo::cuda::rv64;
static void put(uint32_t* out, OM31 a) {
    for (uint32_t c = 0; c < 8; ++c) out[c] = coordinate(a, c);
}
extern "C" void rv64_test_mul(const uint32_t* a, const uint32_t* b, uint32_t* out) {
    put(out, mul(from_words(a), from_words(b)));
}
extern "C" void rv64_test_combine(const uint32_t* a, const uint32_t* b, const uint32_t* c,
                                  const uint32_t* d, uint32_t* out) {
    const auto r = combine({from_words(a), from_words(b)}, {from_words(c), from_words(d)});
    put(out, r.n);
    put(out + 8, r.d);
}
extern "C" void rv64_test_sum(const uint32_t* n, const uint32_t* d, const uint32_t* eq,
                              const uint32_t* lambda, uint32_t count, uint32_t base_n,
                              uint32_t* out) {
    Pair sum{zero(), zero()};
    const uint32_t terms = count / 4;
    for (uint32_t i = 0; i < terms; ++i) {
        const uint32_t j = 2 * i, k = 2 * (terms + i);
        const auto den = [&](uint32_t x) { return from_words(d + 8 * x); };
        const auto num = [&](uint32_t x) { return from_words(n + 8 * x); };
        Pair t;
        if (base_n)
            t = sum_term_base(n[8 * j], den(j), n[8 * (j + 1)], den(j + 1), n[8 * k], den(k),
                              n[8 * (k + 1)], den(k + 1), from_words(eq + 8 * i),
                              from_words(lambda));
        else
            t = sum_term({num(j), den(j)}, {num(j + 1), den(j + 1)}, {num(k), den(k)},
                         {num(k + 1), den(k + 1)}, from_words(eq + 8 * i), from_words(lambda));
        sum.at0 = add(sum.at0, t.at0);
        sum.at2 = add(sum.at2, t.at2);
    }
    put(out, sum.at0);
    put(out + 8, sum.at2);
}
