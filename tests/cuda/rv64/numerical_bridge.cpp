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

#include "rv64/round.cuh"
#include <vector>
#include <cstring>
extern "C" void rv64_test_inverse(const uint32_t* a, uint32_t* out) {
    put(out, inverse_nonzero(from_words(a)));
}
extern "C" void rv64_test_sumcheck(const uint32_t* n, const uint32_t* d, uint32_t count,
                                   uint32_t base_n, const uint32_t* point,
                                   const uint32_t* lambda, const uint32_t* claim,
                                   const uint32_t* seed, uint32_t* records, uint32_t* state,
                                   uint32_t* terminal) {
    uint32_t variables = 0;
    for (uint32_t m = count / 2; m > 1; m >>= 1) ++variables;
    auto* s = reinterpret_cast<RoundState*>(state);
    initialize_round(s, seed, from_words(claim), variables);
    std::vector<Fraction> values(count);
    for (uint32_t i = 0; i < count; ++i)
        values[i] = {base_n ? base(n[8 * i]) : from_words(n + 8 * i), from_words(d + 8 * i)};
    std::vector<OM31> eq(count / 4);
    for (uint32_t i = 0; i < eq.size(); ++i) {
        OM31 e = sub(one(), from_words(point));
        for (uint32_t j = 1; j < variables; ++j) {
            const auto y = from_words(point + 8 * j);
            e = mul(e, i & (1u << (variables - 1 - j)) ? y : sub(one(), y));
        }
        eq[i] = e;
    }
    for (uint32_t round = 0; round < variables; ++round) {
        Pair raw{zero(), zero()};
        const uint32_t terms = values.size() / 4;
        for (uint32_t i = 0; i < terms; ++i) {
            const auto t = sum_term(values[2 * i], values[2 * i + 1], values[2 * (terms + i)],
                                    values[2 * (terms + i) + 1], eq[i], from_words(lambda));
            raw.at0 = add(raw.at0, t.at0);
            raw.at2 = add(raw.at2, t.at2);
        }
        auto* record = reinterpret_cast<RoundRecord*>(records + round * round_record_words);
        if (!advance_round(s, round, raw, from_words(point + 8 * round), record)) return;
        const auto x = record->challenge;
        const size_t half = values.size() / 2;
        for (size_t i = 0; i < half; ++i)
            values[i] = {fold(values[i].n, values[i + half].n, x),
                         fold(values[i].d, values[i + half].d, x)};
        values.resize(half);
    }
    put(terminal, values[0].n);
    put(terminal + 8, values[1].n);
    put(terminal + 16, values[0].d);
    put(terminal + 24, values[1].d);
}
extern "C" uint32_t rv64_test_round_failure(uint32_t kind) {
    uint32_t seed[9]{};
    RoundState state{};
    RoundRecord record{};
    initialize_round(&state, seed, one(), 2);
    OM31 y = base(3);
    if (kind == 0) y = one();                 // zero Eq prefix
    if (kind == 1) y = base(1073741824u);     // 1-2*y=0
    if (kind == 2) y = zero();                // interpolation root b=1
    if (kind == 3) y = base(q::inverse(3u));  // interpolation root b=2
    Pair raw{one(), one()};
    if (kind == 4) {
        uint32_t invalid[8] = {0x7fffffffu};
        y = from_words(invalid);
    }
    advance_round(&state, kind == 5 ? 1 : 0, raw, y, &record);
    return state.status;
}
extern "C" uint32_t rv64_test_round_polynomial(const uint32_t* r0, const uint32_t* r2,
                                               const uint32_t* claim, const uint32_t* y,
                                               uint32_t* coefficients) {
    RoundState state{};
    RoundRecord record{};
    uint32_t seed[9]{};
    initialize_round(&state, seed, from_words(claim), 1);
    if (advance_round(&state, 0, {from_words(r0), from_words(r2)}, from_words(y), &record)) {
        for (uint32_t i = 0; i < 4; ++i) put(coefficients + 8 * i, record.coefficients[i]);
    }
    return state.status;
}
