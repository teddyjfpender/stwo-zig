// arith256_mod glue (our code): the candidate service in candidate builds, a
// software fallback otherwise (only referenced when CANDIDATE_SERVICES is set).
#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>

#include "services.hpp"

extern "C" void stwo_arith256_mod(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                                  const uint64_t m[4], uint64_t r[4]) noexcept {
#if defined(CANDIDATE_ARITH)
    alignas(8) uint64_t p[20];
    std::memcpy(p, a, 32);
    std::memcpy(p + 4, b, 32);
    std::memcpy(p + 8, c, 32);
    std::memcpy(p + 12, m, 32);
    stwo::ecall(stwo::kCandArith256Mod, p);
    std::memcpy(r, p + 16, 32);
#else
    intx::uint256 x, y, z, mm;
    for (int i = 0; i < 4; ++i) { x[i] = a[i]; y[i] = b[i]; z[i] = c[i]; mm[i] = m[i]; }
    intx::uint256 res = 0;
    if (mm != 0) res = static_cast<intx::uint256>((intx::umul(x, y) + intx::uint512{z}) % intx::uint512{mm});
    for (int i = 0; i < 4; ++i) r[i] = res[i];
#endif
}

// lo = low 256 bits of a*b (candidate arith256 with c = 0; EVM MUL). Only
// referenced with CANDIDATE_MUL.
extern "C" void stwo_arith256_lo(const uint64_t a[4], const uint64_t b[4], uint64_t lo[4]) noexcept {
#if defined(CANDIDATE_MUL)
    alignas(8) uint64_t p[20] = {};
    std::memcpy(p, a, 32);
    std::memcpy(p + 4, b, 32);
    stwo::ecall(stwo::kCandArith256, p);
    std::memcpy(lo, p + 12, 32);
#else
    intx::uint256 x, y;
    for (int i = 0; i < 4; ++i) { x[i] = a[i]; y[i] = b[i]; }
    const intx::uint256 r = x * y;
    for (int i = 0; i < 4; ++i) lo[i] = r[i];
#endif
}
