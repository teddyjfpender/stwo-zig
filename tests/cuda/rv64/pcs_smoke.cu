// Real-device OM31 PCS primitive parity and custody. No accepting proof path.
#include "../blake2s_reference.h"
#include "context_owner.cuh"
#include "rv64/om31.cuh"
#include "rv64/pcs.h"
#include <cstring>
using namespace stwo::cuda::rv64;
constexpr uint32_t guard = 0xdeadbeefu;
static OM31 random_value(uint32_t seed) {
    uint32_t w[8];
    for (auto &x : w) {
        seed = 1664525u * seed + 1013904223u;
        x = seed % 2147483647u;
    }
    return from_words(w);
}
static void same(const std::vector<uint32_t> &a, const std::vector<uint32_t> &b,
                 const char *label) {
    if (a != b) {
        for (size_t i = 0; i < std::min(a.size(), b.size()); ++i)
            if (a[i] != b[i]) {
                std::fprintf(stderr, "%s word=%zu got=%u expected=%u\n", label, i, a[i], b[i]);
                break;
            }
        throw std::runtime_error(std::string("OM31 PCS mismatch: ") + label);
    }
}
static void exercise(uint32_t count, uint32_t steps, bool circle, bool accumulate) {
    Owner o(0);
    const uint32_t result_count = count >> steps;
    const auto input = o.plane(count + 3, 8), output = o.plane(result_count + 5, 8),
               twiddles = o.plane(2 * count + 16, 1), alpha = o.plane(1, 8);
    std::vector<uint32_t> in(input.stride * 8, guard), out(output.stride * 8, guard),
        tw(twiddles.stride), av(8);
    std::vector<OM31> current(count);
    for (uint32_t i = 0; i < count; ++i) {
        current[i] = random_value(97 + i);
        store(in.data(), input.stride, i, current[i]);
    }
    const OM31 a = random_value(37);
    for (uint32_t c = 0; c < 8; ++c)
        av[c] = coordinate(a, c);
    for (uint32_t i = 0; i < tw.size(); ++i)
        tw[i] = (i * 31 + 19) % 2147483646u + 1;
    for (uint32_t i = 0; i < result_count; ++i)
        store(out.data(), output.stride, i, random_value(201 + i));
    const auto before = out;
    o.upload(input, in);
    o.upload(output, out);
    o.upload(twiddles, tw);
    o.upload(alpha, av);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    StwoRv64FriFold job{input,
                        output,
                        twiddles.words,
                        tw.size(),
                        alpha.words,
                        {1, count + 2, count + count / 2 + 3, count + count / 2 + count / 4 + 4},
                        count,
                        steps,
                        uint32_t(circle),
                        uint32_t(accumulate)};
    // All invalid descriptors must fail before enqueue, including late ranges.
    auto reject = [&](StwoRv64FriFold bad) {
        if (stwo_rv64_fri_fold_on(o.ctx, 1, &bad) != int(cudaErrorInvalidValue))
            throw std::runtime_error("invalid OM31 FRI descriptor accepted");
    };
    auto bad = job;
    bad.output = input;
    reject(bad);
    bad = job;
    bad.offsets[steps - 1] = uint32_t(tw.size());
    reject(bad);
    bad = job;
    bad.output.stride = result_count - 1;
    reject(bad);
    bad = job;
    bad.steps = 0;
    reject(bad);
    bad = job;
    bad.alpha = output.words;
    reject(bad);
    CHECK(stwo_rv64_fri_fold_on(o.ctx, 1, &job));
    OM31 power = a;
    for (uint32_t s = 0; s < steps; ++s) {
        std::vector<OM31> next(current.size() / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            uint32_t x;
            if (circle && s == 0) {
                const uint32_t at = job.offsets[0] + 2 * (i / 4);
                const auto u = tw[at], v = tw[at + 1];
                x = (i % 4 == 0)   ? v
                    : (i % 4 == 1) ? q::sub(0, v)
                    : (i % 4 == 2) ? q::sub(0, u)
                                   : u;
            } else
                x = tw[job.offsets[s] + i];
            next[i] = add(add(current[2 * i], current[2 * i + 1]),
                          scale(mul(power, sub(current[2 * i], current[2 * i + 1])), x));
        }
        current = std::move(next);
        power = mul(power, power);
    }
    for (uint32_t i = 0; i < result_count; ++i) {
        auto v = current[i];
        if (accumulate)
            v = add(v, mul(power, load(before.data(), output.stride, i)));
        store(out.data(), output.stride, i, v);
    }
    same(o.read(output), out, "fold/guards");
    same(o.read(input), in, "source unchanged");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
}
static void leaves(uint32_t count, uint32_t log, bool prefixed) {
    Owner o(0);
    const uint32_t n = count >> log;
    const auto input = o.plane(count + 3, 8), output = o.plane(8 * n + 8, 1);
    std::vector<uint32_t> in(input.stride * 8, guard), out(output.stride, guard);
    for (uint32_t i = 0; i < count; ++i)
        store(in.data(), input.stride, i, random_value(99 + i));
    o.upload(input, in);
    o.upload(output, out);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    if (stwo_rv64_fri_leaves_on(o.ctx, 1, input, count, log, prefixed, output.words, n - 1) !=
        int(cudaErrorInvalidValue))
        throw std::runtime_error("short leaf output accepted");
    if (stwo_rv64_fri_leaves_on(o.ctx, 1, input, count, log, prefixed, input.words, n) !=
        int(cudaErrorInvalidValue))
        throw std::runtime_error("aliased leaf output accepted");
    CHECK(stwo_rv64_fri_leaves_on(o.ctx, 1, input, count, log, prefixed, output.words, n));
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint32_t> words;
        for (uint32_t row = 0; row < (1u << log); ++row)
            for (uint32_t c = 0; c < 8; ++c)
                words.push_back(in[c * input.stride + (i << log) + row]);
        const auto h = prefixed ? blake2s_reference::hash_prefixed_words(0x6661656cu, words)
                                : blake2s_reference::hash_words(words);
        std::copy(h.words, h.words + 8, out.begin() + 8 * i);
    }
    same(o.read(output), out, "leaf framing/guards");
    same(o.read(input), in, "leaf input unchanged");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
}
int main() {
    try {
        uint32_t cases = 0;
        for (uint32_t log : {1, 2, 3, 4, 5, 8, 10, 16}) {
            const uint32_t count = 1u << log;
            for (uint32_t s = 1; s <= std::min(4u, log); ++s) {
                exercise(count, s, false, false);
                exercise(count, s, true, false);
                cases += 2;
            }
            exercise(count, 1, true, true);
            ++cases;
            for (uint32_t l = 0; l <= std::min(4u, log); ++l) {
                leaves(count, l, false);
                leaves(count, l, true);
                cases += 2;
            }
        }
        std::printf("{\"schema\":\"rv64-om31-pcs-smoke-v1\",\"cases\":%u,\"fold_steps\":[1,2,3,4],"
                    "\"leaf_logs\":[0,1,2,3,4],\"guard_and_preflight_verified\":true,"
                    "\"full_block_verified\":false}\n",
                    cases);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
