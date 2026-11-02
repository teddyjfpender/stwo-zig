// Host test for stwo_keccak256_copy (glue/keccak_stwo.cpp, our code): for every
// length 0..700 and source alignment 0..7 the digest equals ethash_keccak256 on
// the same bytes (and the empty-input known answer), the 8-aligned destination
// holds the bytes followed by zeros up to its next word boundary, and nothing
// past that word is written.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

#include <evmone_precompiles/keccak.h>

extern "C" union ethash_hash256 stwo_keccak256_copy(uint8_t* dst, const uint8_t* src, size_t size) noexcept;

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept {
    std::printf("FAIL guest abort: %s\n", why);
    std::exit(1);
}

int main() {
    std::mt19937_64 rng(25);
    alignas(8) static uint8_t src[1024], dst[1024];
    long cases = 0;
    for (size_t n = 0; n <= 700; ++n) {
        for (unsigned off = 0; off < 8; ++off) {
            for (auto& b : src) b = uint8_t(rng());
            for (auto& b : dst) b = 0xA5;
            const auto want = ethash_keccak256(src + off, n);
            const auto got = stwo_keccak256_copy(dst + 8, src + off, n);
            if (std::memcmp(want.bytes, got.bytes, 32) != 0) {
                std::printf("FAIL digest n=%zu off=%u\n", n, off);
                return 1;
            }
            const size_t end = 8 + ((n + 7) & ~size_t(7));
            for (size_t i = 0; i < sizeof dst; ++i) {
                const uint8_t exp = i < 8 || i >= end ? 0xA5 : i < 8 + n ? src[off + i - 8] : 0;
                if (dst[i] != exp) {
                    std::printf("FAIL copy n=%zu off=%u byte %zu\n", n, off, i);
                    return 1;
                }
            }
            ++cases;
        }
    }
    static const uint8_t kEmpty[32] = {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d,
                                       0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
                                       0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70};
    if (std::memcmp(stwo_keccak256_copy(dst, src, 0).bytes, kEmpty, 32) != 0) {
        std::printf("FAIL keccak256(\"\") known answer\n");
        return 1;
    }
    std::printf("keccak_copy ok (%ld cases)\n", cases + 1);
    return 0;
}
