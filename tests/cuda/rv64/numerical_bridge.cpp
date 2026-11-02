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
#include "rv64/fold_sum.cuh"
#include "rv64/tail_math.cuh"
#include <vector>
#include <cstring>
extern "C" void rv64_test_inverse(const uint32_t* a, uint32_t* out) {
    put(out, inverse_nonzero(from_words(a)));
}
static void sumcheck_impl(bool fused, uint32_t tail_count, const uint32_t* n, const uint32_t* d,
                          uint32_t count, uint32_t base_n, const uint32_t* point,
                          const uint32_t* lambda, const uint32_t* claim, const uint32_t* seed,
                          uint32_t* records, uint32_t* state, uint32_t* terminal) {
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
    Pair next_raw{zero(), zero()};
    for (uint32_t round = 0; round < variables; ++round) {
        if (tail_count && values.size() <= tail_count) {
            // Sequential host replay of shared-table arithmetic helpers only.
            // This deliberately does NOT emulate CUDA barriers or reductions.
            const uint32_t stride = values.size() + 3;
            std::vector<uint32_t> table(16 * stride, 0xdeadbeef), ew(8 * eq.size());
            StwoRv64Plane sn{table.data(), stride, 8, 0},
                sd{table.data() + 8 * stride, stride, 8, 0}, se{ew.data(), eq.size(), 8, 0};
            for (uint32_t i = 0; i < values.size(); ++i) {
                store(sn.words, stride, tail_index(i), values[i].n);
                store(sd.words, stride, tail_index(i), values[i].d);
            }
            for (uint32_t i = 0; i < eq.size(); ++i) store(se.words, se.stride, i, eq[i]);
            uint32_t size = values.size();
            for (uint32_t r = round; r < variables; ++r) {
                Pair raw{zero(), zero()};
                for (uint32_t i = 0; i < size / 4; ++i) {
                    const auto t = tail_term(sn, sd, size, i, se, from_words(lambda));
                    raw.at0 = add(raw.at0, t.at0);
                    raw.at2 = add(raw.at2, t.at2);
                }
                auto* record = reinterpret_cast<RoundRecord*>(records + r * round_record_words);
                advance_record(s, variables, r, raw, from_words(point + 8 * r), record);
                for (uint32_t i = 0; i < size / 2; ++i)
                    tail_fold_row(sn, sd, size / 2, i, record->challenge);
                size /= 2;
            }
            for (uint32_t i = 0; i < 2; ++i) {
                put(terminal + 8 * i, load(sn.words, stride, i));
                put(terminal + 16 + 8 * i, load(sd.words, stride, i));
            }
            return;
        }
        Pair raw = fused && round ? next_raw : Pair{zero(), zero()};
        const uint32_t terms = values.size() / 4;
        for (uint32_t i = 0; !(fused && round) && i < terms; ++i) {
            const auto t = sum_term(values[2 * i], values[2 * i + 1], values[2 * (terms + i)],
                                    values[2 * (terms + i) + 1], eq[i], from_words(lambda));
            raw.at0 = add(raw.at0, t.at0);
            raw.at2 = add(raw.at2, t.at2);
        }
        auto* record = reinterpret_cast<RoundRecord*>(records + round * round_record_words);
        if (!advance_round(s, round, raw, from_words(point + 8 * round), record)) return;
        const auto x = record->challenge;
        const size_t half = values.size() / 2;
        if (fused && half >= 4) {
            // Deliberately padded coordinate strides; disjoint ping-pong planes.
            const uint32_t stride = values.size() + 3, out_stride = half + 5;
            std::vector<uint32_t> ns(8 * stride), ds(8 * stride), on(8 * out_stride),
                od(8 * out_stride);
            const bool base_input = base_n && round == 0;
            for (uint32_t i = 0; i < values.size(); ++i) {
                if (base_input)
                    ns[i] = coordinate(values[i].n, 0);
                else
                    store(ns.data(), stride, i, values[i].n);
                store(ds.data(), stride, i, values[i].d);
            }
            const StwoRv64Plane np{ns.data(), stride, base_input ? 1u : 8u, 0},
                dp{ds.data(), stride, 8, 0}, op{on.data(), out_stride, 8, 0},
                oq{od.data(), out_stride, 8, 0};
            next_raw = {zero(), zero()};
            for (uint32_t i = 0; i < half / 4; ++i) {
                const auto t = fold_sum_tile(np, dp, values.size(), i, x, eq[i],
                                             from_words(lambda), op, oq);
                next_raw.at0 = add(next_raw.at0, t.at0);
                next_raw.at2 = add(next_raw.at2, t.at2);
            }
            for (uint32_t i = 0; i < half; ++i)
                values[i] = {load(on.data(), out_stride, i), load(od.data(), out_stride, i)};
        } else {
            for (size_t i = 0; i < half; ++i)
                values[i] = {fold(values[i].n, values[i + half].n, x),
                             fold(values[i].d, values[i + half].d, x)};
        }
        values.resize(half);
    }
    put(terminal, values[0].n);
    put(terminal + 8, values[1].n);
    put(terminal + 16, values[0].d);
    put(terminal + 24, values[1].d);
}
extern "C" void rv64_test_sumcheck(const uint32_t* n, const uint32_t* d, uint32_t count,
                                   uint32_t base_n, const uint32_t* point,
                                   const uint32_t* lambda, const uint32_t* claim,
                                   const uint32_t* seed, uint32_t* records, uint32_t* state,
                                   uint32_t* terminal) {
    sumcheck_impl(false, 0, n, d, count, base_n, point, lambda, claim, seed, records, state,
                  terminal);
}
extern "C" void rv64_test_sumcheck_fused(const uint32_t* n, const uint32_t* d, uint32_t count,
                                         uint32_t base_n, const uint32_t* point,
                                         const uint32_t* lambda, const uint32_t* claim,
                                         const uint32_t* seed, uint32_t* records,
                                         uint32_t* state, uint32_t* terminal) {
    sumcheck_impl(true, 0, n, d, count, base_n, point, lambda, claim, seed, records, state,
                  terminal);
}
extern "C" void rv64_test_sumcheck_tail(const uint32_t* n, const uint32_t* d, uint32_t count,
                                        uint32_t base_n, const uint32_t* point,
                                        const uint32_t* lambda, const uint32_t* claim,
                                        const uint32_t* seed, uint32_t* records,
                                        uint32_t* state, uint32_t* terminal,
                                        uint32_t threshold) {
    sumcheck_impl(false, threshold, n, d, count, base_n, point, lambda, claim, seed, records,
                  state, terminal);
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
#include "rv64/eq_tile.cuh"
extern "C" void rv64_test_eq_fused(const uint32_t* point, uint32_t variables,
                                   uint32_t* output) {
    const uint32_t count = variables ? 1u << (variables - 1) : 1;
    store(output, count, 0, variables ? sub(one(), from_words(point)) : one());
    uint32_t remaining = variables ? variables - 1 : 0, half = 1;
    while (remaining) {
        const uint32_t levels = remaining >= 4 ? 4 : remaining, first = remaining + 1 - levels;
        for (uint32_t i = 0; i < half; ++i) {
            const auto v = load(output, count, i);
            switch (levels) {
                case 4:
                    expand_eq_tile<4>(v, point, first, output, count, i, half);
                    break;
                case 3:
                    expand_eq_tile<3>(v, point, first, output, count, i, half);
                    break;
                case 2:
                    expand_eq_tile<2>(v, point, first, output, count, i, half);
                    break;
                default:
                    expand_eq_tile<1>(v, point, first, output, count, i, half);
                    break;
            }
        }
        half <<= levels;
        remaining -= levels;
    }
}
extern "C" void rv64_test_hash_words(const uint32_t* digest, const uint32_t* suffix,
                                     uint32_t length, uint32_t* output) {
    const auto h = stwo::cuda::transcript::hash_digest_and_words(digest, suffix, length);
    for (uint32_t i = 0; i < 8; ++i) output[i] = h.words[i];
}

extern "C" void rv64_test_tail_indices(uint32_t* output) {
    for (uint32_t i = 0; i < 256; ++i) output[i] = tail_index(i);
}

extern "C" uint32_t rv64_test_owned_failure(uint32_t kind, uint32_t* output) {
    RoundState state{};
    uint32_t seed[9]{};
    initialize_round(&state, seed, one(), 2);
    uint32_t* words = output;
    for (uint32_t i = 0; i < round_record_words; ++i) words[i] = 0xdeadbeef;
    uint32_t variables = 2, expected = 0;
    Pair raw{one(), one()};
    OM31 point = base(3);
    if (kind == 0) state.status = round_pole;
    if (kind == 1) variables = 3;
    if (kind == 2) expected = 1;
    if (kind == 3) point = one();
    if (kind == 4) raw.at0.c0.a.a = q::kPrime;
    advance_record(&state, variables, expected, raw, point,
                   reinterpret_cast<RoundRecord*>(output));
    return state.status;
}
