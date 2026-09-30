#include <cassert>
#include <cstdint>
#include <random>

#define __host__
#define __device__
#define __forceinline__ inline
#include "../../src/backends/cuda/native/common/m31.cuh"

int main() {
    using namespace stwo::cuda;
    constexpr std::uint64_t prime = kM31Prime;
    constexpr std::uint32_t edges[] = {0, 1, 2, 3, 31, 1u << 30,
                                       kM31Prime - 3, kM31Prime - 2,
                                       kM31Prime - 1};
    auto check = [](std::uint32_t left, std::uint32_t right) {
        assert(m31_add(left, right) ==
               (static_cast<std::uint64_t>(left) + right) % prime);
        assert(m31_sub(left, right) ==
               (static_cast<std::uint64_t>(left) + prime - right) % prime);
        assert(m31_mul(left, right) ==
               (static_cast<std::uint64_t>(left) * right) % prime);
        assert(m31_neg(left) == (prime - left) % prime);
    };
    for (auto left : edges)
        for (auto right : edges) check(left, right);
    std::mt19937_64 generator(0x83dba08e935a9105ULL);
    for (std::size_t i = 0; i < 100000; ++i) {
        check(generator() % prime, generator() % prime);
    }
}
