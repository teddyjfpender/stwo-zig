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

// Head of a destination up to its next 8-byte boundary: the high `8 - off`
// bytes of the aligned word at d - off take the low bytes of `w` (one RMW).
static inline void store_head(uint8_t* d, uint64_t w) {
    const unsigned off = reinterpret_cast<uintptr_t>(d) & 7;
    uint8_t* a = d - off;
    const uint64_t keep = (uint64_t(1) << (off * 8)) - 1;  // off in 1..7
    st64(a, (ld64(a) & keep) | (w << (off * 8)));
}
// Tail at an 8-aligned d: the low k bytes (k in 1..7) take the low bytes of `w`.
static inline void store_tail(uint8_t* d, uint64_t w, size_t k) {
    const uint64_t mask = (uint64_t(1) << (8 * k)) - 1;
    st64(d, (ld64(d) & ~mask) | (w & mask));
}

// Forward copy, every access an aligned word. Bodies run on end pointers and,
// for a source misaligned against the destination, a funnel shift unrolled to
// 32 bytes (4 ld, 4 srl, 4 sll, 4 or, 4 sd, 2 addi, 1 bne).
__attribute__((noinline)) static void copy_forward(uint8_t* d, const uint8_t* s, size_t n) {
    if (n <= 8) {
        if (n) store_partial(d, load_unaligned(s, n), n);
        return;
    }
    // Head: bring d to an 8-byte boundary.
    const size_t head = (0 - reinterpret_cast<uintptr_t>(d)) & 7;
    if (head) {
        store_head(d, load_unaligned(s, n));
        d += head; s += head; n -= head;
    }
    const size_t body = n & ~size_t(7);
    const size_t rem = n & 7;
    uint8_t* const end = d + body;
    uint8_t* const end4 = d + (n & ~size_t(31));
    const uint8_t* const s_tail = s + body;
    const unsigned off = reinterpret_cast<uintptr_t>(s) & 7;
    if (off == 0) {
        while (d != end4) {
            const uint64_t a = ld64(s), b = ld64(s + 8), c = ld64(s + 16), e = ld64(s + 24);
            st64(d, a); st64(d + 8, b); st64(d + 16, c); st64(d + 24, e);
            d += 32; s += 32;
        }
        while (d != end) { st64(d, ld64(s)); d += 8; s += 8; }
    } else {
        // Funnel shift from aligned source words; reads only words that hold
        // a byte of the range (word k+1 holds source byte 8k+7).
        const unsigned shift = off * 8;
        const unsigned rs = 64 - shift;
        const uint8_t* sa = s - off;
        uint64_t lo = ld64(sa);
        while (d != end4) {
            const uint64_t m1 = ld64(sa + 8), m2 = ld64(sa + 16), m3 = ld64(sa + 24), m4 = ld64(sa + 32);
            st64(d, (lo >> shift) | (m1 << rs));
            st64(d + 8, (m1 >> shift) | (m2 << rs));
            st64(d + 16, (m2 >> shift) | (m3 << rs));
            st64(d + 24, (m3 >> shift) | (m4 << rs));
            lo = m4;
            sa += 32; d += 32;
        }
        while (d != end) {
            const uint64_t h = ld64(sa + 8);
            st64(d, (lo >> shift) | (h << rs));
            lo = h;
            sa += 8; d += 8;
        }
    }
    if (rem) store_tail(end, load_unaligned(s_tail, rem), rem);
}

// Service copy/fill split (runtime.cpp, admitted v3 bulk memory): for n >= 15
// the destination has at least one whole aligned word; its unaligned head and
// tail are one aligned read-modify-write word each and `body(d, s|byte, len)`
// gets an 8-aligned d and a nonzero multiple of 8. Tested by tests/mem_fuzz.cpp.
template <class Body>
static inline void split_copy(uint8_t* dp, const uint8_t* sp, size_t n, Body body) {
    const size_t head = (0 - reinterpret_cast<uintptr_t>(dp)) & 7;
    const size_t len = (n - head) & ~size_t(7);
    const size_t tail = n - head - len;
    if (head) store_head(dp, load_unaligned(sp, n));
    body(dp + head, sp + head, len);
    if (tail) store_tail(dp + head + len, load_unaligned(sp + head + len, tail), tail);
}
template <class Body>
static inline void split_fill(uint8_t* dp, int c, size_t n, Body body) {
    const size_t head = (0 - reinterpret_cast<uintptr_t>(dp)) & 7;
    const size_t len = (n - head) & ~size_t(7);
    const size_t tail = n - head - len;
    const uint8_t byte = static_cast<uint8_t>(c);
    const uint64_t w = uint64_t(byte) * 0x0101010101010101ull;
    if (head) store_head(dp, w);
    body(dp + head, byte, len);
    if (tail) store_tail(dp + head + len, w, tail);
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
    const uint64_t w = uint64_t(static_cast<uint8_t>(c)) * 0x0101010101010101ull;
    if (n <= 8) {
        if (n) store_partial(d, w, n);
        return dst;
    }
    const size_t head = (0 - reinterpret_cast<uintptr_t>(d)) & 7;
    if (head) { store_head(d, w); d += head; n -= head; }
    uint8_t* const end = d + (n & ~size_t(7));
    uint8_t* const end4 = d + (n & ~size_t(31));
    while (d != end4) { st64(d, w); st64(d + 8, w); st64(d + 16, w); st64(d + 24, w); d += 32; }
    while (d != end) { st64(d, w); d += 8; }
    if (n & 7) store_tail(d, w, n & 7);
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

