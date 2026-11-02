// Sanitized host execution of the exact numerical headers, not CUDA emulation.
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>
extern "C" void rv64_test_sumcheck(const uint32_t*, const uint32_t*, uint32_t, uint32_t,
                                   const uint32_t*, const uint32_t*, const uint32_t*,
                                   const uint32_t*, uint32_t*, uint32_t*, uint32_t*);
extern "C" void rv64_test_sumcheck_fused(const uint32_t*, const uint32_t*, uint32_t, uint32_t,
                                         const uint32_t*, const uint32_t*, const uint32_t*,
                                         const uint32_t*, uint32_t*, uint32_t*, uint32_t*);
extern "C" void rv64_test_sumcheck_tail(const uint32_t*, const uint32_t*, uint32_t, uint32_t,
                                        const uint32_t*, const uint32_t*, const uint32_t*,
                                        const uint32_t*, uint32_t*, uint32_t*, uint32_t*,
                                        uint32_t);
int main() {
    uint32_t random = 731;
    const auto word = [&]() {
        random = random * 1664525u + 1013904223u;
        return random % 2147483647u;
    };
    for (uint32_t log = 2; log <= 12; ++log) {
        const uint32_t count = 1u << log, variables = log - 1;
        for (uint32_t base = 0; base < 2; ++base) {
            std::vector<uint32_t> n(8 * count), d(8 * count), point(8 * variables);
            for (auto& v : n) v = word();
            for (auto& v : d) v = word();
            for (auto& v : point) v = word();
            std::array<uint32_t, 8> lambda{}, claim{};
            std::array<uint32_t, 9> seed{};
            for (auto& v : lambda) v = word();
            for (auto& v : claim) v = word();
            for (auto& v : seed) v = word();
            const auto original_n = n, original_d = d, original_point = point;
            std::vector<uint32_t> a(44 * variables, 0xdeadbeef), b = a;
            std::array<uint32_t, 40> sa{}, sb{};
            std::array<uint32_t, 32> ta{}, tb{};
            rv64_test_sumcheck(n.data(), d.data(), count, base, point.data(), lambda.data(),
                               claim.data(), seed.data(), a.data(), sa.data(), ta.data());
            rv64_test_sumcheck_fused(n.data(), d.data(), count, base, point.data(),
                                     lambda.data(), claim.data(), seed.data(), b.data(),
                                     sb.data(), tb.data());
            assert(sa[10] == 0 && sa[9] == variables);
            assert(a == b && sa == sb && ta == tb);
            for (uint32_t threshold : {4u, 8u, 16u, 64u, 256u}) {
                rv64_test_sumcheck_tail(n.data(), d.data(), count, base, point.data(),
                                        lambda.data(), claim.data(), seed.data(), b.data(),
                                        sb.data(), tb.data(), threshold);
                assert(a == b && sa == sb && ta == tb);
            }
            assert(n == original_n && d == original_d && point == original_point);
        }
    }
}
