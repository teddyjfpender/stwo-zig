// Memory functions of the RV64IM guest runtime (our code), shared by
// runtime.cpp (the libc symbols) and tests/mem_fuzz.cpp. The executor traps on
// misaligned loads/stores, so every word access is naturally aligned:
// head/tail bytes go through aligned read-modify-write words and unaligned
// sources through a funnel shift that never reads a word holding no byte of
// the source range.
#pragma once
#include <cstddef>
#include <cstdint>

static inline uint64_t ld64(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }
static inline void st64(uint8_t* p, uint64_t v) { *reinterpret_cast<uint64_t*>(p) = v; }

// Bytes [s, s+8) assembled from the aligned words that hold them. Only words
// containing at least one byte of [s, s + avail) are read (avail >= 1).
static inline uint64_t load_unaligned(const uint8_t* s, size_t avail) {
    const unsigned off = reinterpret_cast<uintptr_t>(s) & 7;
    const uint8_t* a = s - off;
    if (off == 0) return ld64(a);
    const uint64_t lo = ld64(a) >> (off * 8);
    if (off + avail <= 8) return lo;
    return lo | (ld64(a + 8) << (64 - off * 8));
}

// Write the low `k` bytes of `w` to d[0..k) (k in 1..8) with one aligned
// read-modify-write per touched word; bytes outside the range keep their value.
static inline void store_partial(uint8_t* d, uint64_t w, size_t k) {
    const unsigned off = reinterpret_cast<uintptr_t>(d) & 7;
    uint8_t* a = d - off;
    const uint64_t mask = k >= 8 ? ~uint64_t(0) : ((uint64_t(1) << (8 * k)) - 1);
    const uint64_t m0 = mask << (off * 8);
    st64(a, (ld64(a) & ~m0) | ((w << (off * 8)) & m0));
    if (off + k > 8) {
        const uint64_t m1 = mask >> (64 - off * 8);
        st64(a + 8, (ld64(a + 8) & ~m1) | ((w >> (64 - off * 8)) & m1));
    }
}

__attribute__((noinline)) static void copy_forward(uint8_t* d, const uint8_t* s, size_t n) {
    if (n == 0) return;
    if (n <= 8) {
        store_partial(d, load_unaligned(s, n), n);
        return;
    }
    // Head: bring d to an 8-byte boundary.
    const size_t head = (0 - reinterpret_cast<uintptr_t>(d)) & 7;
    if (head) {
        store_partial(d, load_unaligned(s, n), head);
        d += head; s += head; n -= head;
    }
    const unsigned shift = (reinterpret_cast<uintptr_t>(s) & 7) * 8;
    if (shift == 0) {
        while (n >= 32) {
            uint64_t a = ld64(s), b = ld64(s + 8), c = ld64(s + 16), e = ld64(s + 24);
            st64(d, a); st64(d + 8, b); st64(d + 16, c); st64(d + 24, e);
            d += 32; s += 32; n -= 32;
        }
        while (n >= 8) { st64(d, ld64(s)); d += 8; s += 8; n -= 8; }
    } else {
        // Funnel shift from aligned source words; reads only words that hold
        // a byte of the range.
        const uint8_t* sa = s - (shift / 8);
        uint64_t lo = ld64(sa);
        const unsigned rs = 64 - shift;
        while (n >= 16) {
            const uint64_t m = ld64(sa + 8), h = ld64(sa + 16);
            st64(d, (lo >> shift) | (m << rs));
            st64(d + 8, (m >> shift) | (h << rs));
            lo = h;
            sa += 16; d += 16; s += 16; n -= 16;
        }
        if (n >= 8) {
            const uint64_t h = ld64(sa + 8);
            st64(d, (lo >> shift) | (h << rs));
            sa += 8; d += 8; s += 8; n -= 8;
        }
    }
    if (n) st64(d, (ld64(d) & ~((uint64_t(1) << (8 * n)) - 1)) | (load_unaligned(s, n) & ((uint64_t(1) << (8 * n)) - 1)));
}

static inline void* stwo_memcpy(void* dst, const void* src, size_t n) {
    copy_forward(static_cast<uint8_t*>(dst), static_cast<const uint8_t*>(src), n);
    return dst;
}

static inline void* stwo_memmove(void* dst, const void* src, size_t n) {
    uint8_t* d = static_cast<uint8_t*>(dst);
    const uint8_t* s = static_cast<const uint8_t*>(src);
    if (reinterpret_cast<uintptr_t>(d) - reinterpret_cast<uintptr_t>(s) >= n) {
        copy_forward(d, s, n);
    } else {
        // dst overlaps ahead of src: copy backwards (word-wise when co-aligned).
        d += n; s += n;
        if (((reinterpret_cast<uintptr_t>(d) ^ reinterpret_cast<uintptr_t>(s)) & 7) == 0) {
            while (n && (reinterpret_cast<uintptr_t>(d) & 7)) { *--d = *--s; --n; }
            while (n >= 8) { d -= 8; s -= 8; st64(d, ld64(s)); n -= 8; }
        }
        while (n--) *--d = *--s;
    }
    return dst;
}

static inline void* stwo_memset(void* dst, int c, size_t n) {
    uint8_t* d = static_cast<uint8_t*>(dst);
    const uint8_t b = static_cast<uint8_t>(c);
    if (n >= 16) {
        size_t head = (0 - reinterpret_cast<uintptr_t>(d)) & 7;
        n -= head;
        while (head--) *d++ = b;
        const uint64_t w = uint64_t(b) * 0x0101010101010101ull;
        while (n >= 32) { st64(d, w); st64(d + 8, w); st64(d + 16, w); st64(d + 24, w); d += 32; n -= 32; }
        while (n >= 8) { st64(d, w); d += 8; n -= 8; }
    }
    while (n--) *d++ = b;
    return dst;
}

static inline int stwo_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* x = static_cast<const uint8_t*>(a);
    const uint8_t* y = static_cast<const uint8_t*>(b);
    if (n >= 16 && ((reinterpret_cast<uintptr_t>(x) | reinterpret_cast<uintptr_t>(y)) & 7) == 0) {
        while (n >= 8 && ld64(x) == ld64(y)) { x += 8; y += 8; n -= 8; }
    }
    for (; n; --n, ++x, ++y) {
        if (*x != *y) return int(*x) - int(*y);
    }
    return 0;
}

