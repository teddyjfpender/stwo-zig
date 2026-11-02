#pragma once
#include "rv64/round.cuh"
#include <stdexcept>
#include <vector>
extern "C" void rv64_test_sumcheck(const uint32_t*, const uint32_t*, uint32_t, uint32_t,
                                   const uint32_t*, const uint32_t*, const uint32_t*,
                                   const uint32_t*, uint32_t*, uint32_t*, uint32_t*);
namespace stwo::cuda::rv64::fixture {
inline OM31 value(uint32_t seed) {
    uint32_t words[8];
    for (auto& w : words) {
        seed = seed * 1664525u + 1013904223u;
        w = seed % q::kPrime;
    }
    return from_words(words);
}
inline void put(std::vector<uint32_t>& out, size_t i, OM31 v) {
    for (uint32_t c = 0; c < 8; ++c) out[8 * i + c] = coordinate(v, c);
}
// Honest single-oracle claim + host numerical reference, with per-job seeds.
// The reference headers are separately checked against the native Zig prover.
struct Data {
    uint32_t variables = 0;
    std::vector<uint32_t> n_aos, d_aos, n_soa, d_soa, point, lambda, claim, seed;
    std::vector<uint32_t> records, state, terminal;
    Data(uint32_t count, bool base_n, uint32_t ordinal = 0) {
        for (uint32_t m = count / 2; m > 1; m >>= 1) ++variables;
        n_aos.resize(8 * count);
        d_aos.resize(8 * count);
        n_soa.resize(count * (base_n ? 1 : 8));
        d_soa.resize(8 * count);
        point.resize(8 * variables);
        lambda.resize(8);
        claim.resize(8);
        seed.resize(9);
        const auto l = value(9000 + ordinal);
        put(lambda, 0, l);
        for (uint32_t i = 0; i < count; ++i) {
            const auto n = base_n ? base(i * 11 + ordinal) : value(600 + i + ordinal),
                       d = value(100 + i + ordinal);
            put(n_aos, i, n);
            put(d_aos, i, d);
            if (base_n)
                n_soa[i] = coordinate(n, 0);
            else
                store(n_soa.data(), count, i, n);
            store(d_soa.data(), count, i, d);
        }
        for (uint32_t i = 0; i < variables; ++i) put(point, i, value(2000 + i + ordinal));
        OM31 c = zero();
        for (uint32_t i = 0; i < count / 2; ++i) {
            const auto f = combine(
                {from_words(n_aos.data() + 16 * i), from_words(d_aos.data() + 16 * i)},
                {from_words(n_aos.data() + 16 * i + 8), from_words(d_aos.data() + 16 * i + 8)});
            OM31 e = one();
            for (uint32_t j = 0; j < variables; ++j) {
                const auto y = from_words(point.data() + 8 * j);
                e = mul(e, i & (1u << (variables - 1 - j)) ? y : sub(one(), y));
            }
            c = add(c, mul(e, add(f.n, mul(l, f.d))));
        }
        put(claim, 0, c);
        seed[0] = ordinal;
        seed[8] = 3;
        records.resize(variables * round_record_words);
        state.resize(round_state_words);
        terminal.resize(32);
        rv64_test_sumcheck(n_aos.data(), d_aos.data(), count, base_n, point.data(),
                           lambda.data(), claim.data(), seed.data(), records.data(),
                           state.data(), terminal.data());
        if (state[10]) throw std::runtime_error("host numerical reference failed");
    }
};
}  // namespace stwo::cuda::rv64::fixture
