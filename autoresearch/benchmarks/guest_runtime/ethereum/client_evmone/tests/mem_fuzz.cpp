// Host fuzz test for glue/mem_functions.hpp (our code): every alignment of
// source and destination, lengths 0..300, overlapping memmove in both
// directions, memset values and memcmp sign/equality, against byte references.
// Compile with -fno-builtin so the reference loops stay loops.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>

#include "mem_functions.hpp"

int main() {
    alignas(16) static uint8_t a[1024], b[1024], ref[1024];
    std::mt19937_64 rng(7);
    long checks = 0;
    for (int it = 0; it < 400000; ++it) {
        for (auto& x : a) x = uint8_t(rng());
        for (int i = 0; i < 1024; ++i) b[i] = ref[i] = uint8_t(rng());
        const size_t so = rng() % 64, dof = rng() % 64, n = rng() % 300;
        switch (it % 4) {
            case 0: {  // memcpy
                for (size_t i = 0; i < n; ++i) ref[256 + dof + i] = a[so + i];
                stwo_memcpy(b + 256 + dof, a + so, n);
                break;
            }
            case 1: {  // overlapping memmove within one buffer
                const size_t s = 256 + so, d = 256 + dof;
                uint8_t tmp[400];
                for (size_t i = 0; i < n; ++i) tmp[i] = ref[s + i];
                for (size_t i = 0; i < n; ++i) ref[d + i] = tmp[i];
                stwo_memmove(b + d, b + s, n);
                break;
            }
            case 2: {  // memset
                const int c = int(rng() & 0x1ff);
                for (size_t i = 0; i < n; ++i) ref[256 + dof + i] = uint8_t(c);
                stwo_memset(b + 256 + dof, c, n);
                break;
            }
            case 3: {  // memcmp on equal prefix then a difference (or none)
                for (size_t i = 0; i < n; ++i) a[256 + dof + i] = a[so + i];
                const bool differ = n && (rng() & 1);
                size_t k = differ ? rng() % n : 0;
                if (differ) a[256 + dof + k] ^= uint8_t(1 + rng() % 255);
                const int got = stwo_memcmp(a + so, a + 256 + dof, n);
                int want = 0;
                for (size_t i = 0; i < n; ++i)
                    if (a[so + i] != a[256 + dof + i]) { want = a[so + i] < a[256 + dof + i] ? -1 : 1; break; }
                if ((got < 0) != (want < 0) || (got > 0) != (want > 0)) {
                    std::printf("memcmp FAIL so=%zu do=%zu n=%zu\n", so, dof, n);
                    return 1;
                }
                ++checks;
                continue;
            }
        }
        if (std::memcmp(b, ref, sizeof b) != 0) {  // whole buffer: no stray writes
            std::printf("FAIL op=%d so=%zu do=%zu n=%zu\n", it % 4, so, dof, n);
            return 1;
        }
        ++checks;
    }
    std::printf("mem_fuzz ok (%ld checks)\n", checks);
    return 0;
}
