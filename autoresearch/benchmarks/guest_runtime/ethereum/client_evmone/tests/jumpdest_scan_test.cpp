// Host test for the RV64 sentinel JUMPDEST scan (patches 0008, 0014; our
// code): the guest-only analyze_jumpdests_sentinel must give the same bitmap
// as evmone's reference analyze_jumpdests_sw for random codes biased towards
// PUSH/JUMPDEST/0x5c-0x5f bytes, truncated trailing PUSHes, every length
// 0..400, and must restore the 33 zero padding bytes.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it; includes the
// staged lib/evmone/baseline_analysis.cpp so the anonymous-namespace scans
// are reachable)
#include "lib/evmone/baseline_analysis.cpp"

#include <cstdio>
#include <random>
#include <vector>

int main()
{
    std::mt19937_64 rng(28);
    long cases = 0;
    for (int it = 0; it < 200000; ++it)
    {
        const size_t n = it < 401 ? size_t(it) : rng() % 3000;
        const size_t padded_size = (n + 33 + 7) / 8 * 8;
        const size_t words = (n + 64) / 64;
        std::vector<uint64_t> buf(padded_size / 8 + 1), m1(words), m2(words);
        auto* code = reinterpret_cast<uint8_t*>(buf.data());
        for (size_t i = 0; i < n; ++i)
        {
            const unsigned r = rng() % 8;
            code[i] = r < 3 ? uint8_t(0x5b + rng() % 37) : r < 4 ? uint8_t(0x5b) : uint8_t(rng());
        }
        evmone::baseline::analyze_jumpdests_sw(evmone::BitsetSpan{m1.data()}, {code, n});
        evmone::baseline::analyze_jumpdests_sentinel(evmone::BitsetSpan{m2.data()}, code, n);
        if (m1 != m2)
        {
            std::printf("FAIL jumpdest bitmap n=%zu it=%d\n", n, it);
            return 1;
        }
        for (size_t i = n; i < n + 33; ++i)
            if (code[i] != 0)
            {
                std::printf("FAIL padding not restored n=%zu\n", n);
                return 1;
            }
        ++cases;
    }
    std::printf("jumpdest_scan ok (%ld codes)\n", cases);
    return 0;
}
