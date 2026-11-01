// Freestanding runtime for the evmone-class RV64IM guest (our code).
//
// The guest links with -nostdlib: libc++ is used header-only (plus the one
// out-of-line hash.cpp for __next_prime) and every libc symbol the C++ sources
// reference is provided here. The executor traps on misaligned loads and
// stores, so the memory functions only issue naturally aligned accesses
// (same design as ethereum/rv64/mem, the Rust guest's memory crate).
//
// Allocation: power-of-two size classes with per-class free lists over a bump
// region [__heap_start, __heap_end). ziskethone's ZisK build relies on a
// never-freeing bump heap plus a per-transaction arena; its host code paths
// (used here) free normally, so blocks are recycled instead of leaked. A
// 16-byte header holds the class; payloads stay 16-byte aligned.
#include <cstddef>
#include <cstdint>
#include <new>

extern "C" {
extern char __heap_start[];
extern char __heap_end[];

[[noreturn]] void stwo_guest_abort(const char* why) noexcept;

static char* g_next = nullptr;
static char* g_tx_low = nullptr;  // per-transaction arena grows down from the top
static void* g_free[96];          // free list heads per size class

static inline void heap_init() {
    if (!g_next) {
        g_next = __heap_start;
        g_tx_low = __heap_end;
    }
}

[[noreturn]] static void out_of_memory() { stwo_guest_abort("out of memory"); }

// Classes 1..64: blocks of 32*c bytes (header included); classes 65..:
// powers of two from 4 KiB (2^(c-53)).
static inline unsigned size_class(size_t size) {
    const size_t total = size + 16;
    if (total <= 2048) return static_cast<unsigned>((total + 31) >> 5);
    return 53 + (64 - __builtin_clzll(total - 1));  // 53 + ceil(log2(total))
}
static inline size_t class_block(unsigned c) {
    return c <= 64 ? size_t(c) << 5 : size_t(1) << (c - 53);
}

// Requests above kLargeLimit are exact-size (16-byte granularity) blocks on a
// first-fit free list, so a one-off 85 MiB arena does not round up to 128 MiB.
static constexpr size_t kLargeLimit = size_t(1) << 20;
static constexpr uint64_t kLargeTag = 200;
static constexpr uint64_t kPinnedTag = 201;
struct LargeFree { LargeFree* next; size_t cap; };
static LargeFree* g_large = nullptr;

static inline char* bump(size_t block) {
    heap_init();
    char* p = g_next;
    if (block > static_cast<size_t>(g_tx_low - p)) out_of_memory();
    g_next = p + block;
    return p;
}

__attribute__((noinline)) static char* large_alloc(size_t size) {
    size = (size + 15) & ~size_t(15);
    for (LargeFree** pp = &g_large; *pp; pp = &(*pp)->next) {
        if ((*pp)->cap >= size) {
            LargeFree* f = *pp;
            *pp = f->next;
            return reinterpret_cast<char*>(f);
        }
    }
    char* p = bump(size + 16);
    reinterpret_cast<uint64_t*>(p)[0] = kLargeTag;
    reinterpret_cast<uint64_t*>(p)[1] = size;
    return p + 16;
}

static inline char* heap_alloc(size_t size) {
    if (size > kLargeLimit) return large_alloc(size);
    const unsigned c = size_class(size);
    void* head = g_free[c];
    if (head) {
        g_free[c] = *static_cast<void**>(head);
        return static_cast<char*>(head);
    }
    char* p = bump(class_block(c));
    *reinterpret_cast<uint64_t*>(p) = c;
    return p + 16;
}

static inline void heap_free(void* ptr) {
    if (!ptr) return;
    char* p = static_cast<char*>(ptr);
    const uint64_t c = *reinterpret_cast<uint64_t*>(p - 16);
    if (c == kLargeTag) {
        LargeFree* f = static_cast<LargeFree*>(ptr);
        f->cap = reinterpret_cast<uint64_t*>(p - 16)[1];
        f->next = g_large;
        g_large = f;
        return;
    }
    if (c == kPinnedTag) return;
    *static_cast<void**>(ptr) = g_free[c];
    g_free[c] = ptr;
}

static inline size_t heap_capacity(void* ptr) {
    const uint64_t* h = reinterpret_cast<uint64_t*>(static_cast<char*>(ptr) - 16);
    if (h[0] == kLargeTag) return h[1];
    return class_block(static_cast<unsigned>(h[0])) - 16;
}

void* zeg_tx_arena_alloc(size_t size) noexcept {
    heap_init();
    size = (size + 15) & ~size_t(15);
    if (size > static_cast<size_t>(g_tx_low - g_next)) out_of_memory();
    g_tx_low -= size;
    return g_tx_low;
}
void zeg_tx_arena_reset() noexcept {
    heap_init();
    g_tx_low = __heap_end;
}
size_t stwo_heap_used() noexcept {
    heap_init();
    return static_cast<size_t>(g_next - __heap_start);
}

void* memcpy(void* dst, const void* src, size_t n);
void* memset(void* dst, int c, size_t n);

void* malloc(size_t size) { return heap_alloc(size); }
void free(void* p) { heap_free(p); }
void* calloc(size_t n, size_t size) {
    void* p = heap_alloc(n * size);
    memset(p, 0, n * size);
    return p;
}
void* realloc(void* ptr, size_t size) {
    if (!ptr) return heap_alloc(size);
    const size_t cap = heap_capacity(ptr);
    if (size <= cap) return ptr;
    char* p = heap_alloc(size);
    memcpy(p, ptr, cap);
    heap_free(ptr);
    return p;
}
void* aligned_alloc(size_t alignment, size_t size) {
    if (alignment <= 16) return heap_alloc(size);
    // Over-aligned requests are rare; serve them from the bump region, never freed.
    heap_init();
    uintptr_t cur = reinterpret_cast<uintptr_t>(g_next) + 16;
    uintptr_t aligned = (cur + (alignment - 1)) & ~(uintptr_t)(alignment - 1);
    const size_t need = aligned - reinterpret_cast<uintptr_t>(g_next) + size;
    if (need > static_cast<size_t>(g_tx_low - g_next)) out_of_memory();
    g_next += (need + 15) & ~size_t(15);
    *reinterpret_cast<uint64_t*>(aligned - 16) = kPinnedTag;  // never on a free list
    return reinterpret_cast<void*>(aligned);
}
int posix_memalign(void** out, size_t alignment, size_t size) {
    *out = aligned_alloc(alignment, size);
    return 0;
}

// ----- memory functions: aligned-only word loops ---------------------------
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

void* memcpy(void* dst, const void* src, size_t n) {
    copy_forward(static_cast<uint8_t*>(dst), static_cast<const uint8_t*>(src), n);
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
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

void* memset(void* dst, int c, size_t n) {
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

int memcmp(const void* a, const void* b, size_t n) {
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
int bcmp(const void* a, const void* b, size_t n) { return memcmp(a, b, n); }

size_t strlen(const char* s) { size_t n = 0; while (s[n]) ++n; return n; }
int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return int((unsigned char)*a) - int((unsigned char)*b);
}

// ----- stdio / environment stubs (diagnostics only; no output channel) ----
struct _IO_FILE;
typedef struct _IO_FILE FILE;
static char g_file_storage[2][16];
extern FILE* const stderr;
extern FILE* const stdout;
FILE* const stderr = reinterpret_cast<FILE*>(g_file_storage[0]);
FILE* const stdout = reinterpret_cast<FILE*>(g_file_storage[1]);
int atoi(const char*) { return 0; }

// Single-threaded atomics used by libc++'s memory_resource.cpp.
uint64_t __atomic_load_8(const volatile void* p, int) { return *static_cast<const volatile uint64_t*>(p); }
uint64_t __atomic_exchange_8(volatile void* p, uint64_t v, int) {
    volatile uint64_t* q = static_cast<volatile uint64_t*>(p);
    const uint64_t old = *q;
    *q = v;
    return old;
}
int fprintf(FILE*, const char*, ...) { return 0; }
int printf(const char*, ...) { return 0; }
int fputc(int c, FILE*) { return c; }
int fputs(const char*, FILE*) { return 0; }
int puts(const char*) { return 0; }
int putchar(int c) { return c; }
size_t fwrite(const void*, size_t, size_t n, FILE*) { return n; }
int fflush(FILE*) { return 0; }
char* getenv(const char*) { return nullptr; }
void abort() { stwo_guest_abort("abort"); }

int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
int atexit(void (*)(void)) { return 0; }
void* __dso_handle = nullptr;
int __cxa_guard_acquire(uint64_t* g) { return !*reinterpret_cast<char*>(g); }
void __cxa_guard_release(uint64_t* g) { *reinterpret_cast<char*>(g) = 1; }
void __cxa_guard_abort(uint64_t*) {}
[[noreturn]] void __cxa_pure_virtual() { stwo_guest_abort("pure virtual"); }

float ceilf(float x) {
    // Only used by unordered_map's load-factor arithmetic on small values.
    long long i = static_cast<long long>(x);
    float f = static_cast<float>(i);
    return f < x ? f + 1.0f : f;
}
double ceil(double x) {
    long long i = static_cast<long long>(x);
    double f = static_cast<double>(i);
    return f < x ? f + 1.0 : f;
}
}  // extern "C"

namespace std {
inline namespace __1 {
[[noreturn]] void __libcpp_verbose_abort(const char*, ...) noexcept { stwo_guest_abort("libc++ abort"); }
// Single-threaded: libc++'s mutex (memory_resource.cpp) is a no-op.
class mutex {
public:
    ~mutex();
    void lock();
    void unlock() noexcept;
};
mutex::~mutex() {}
void mutex::lock() {}
void mutex::unlock() noexcept {}
}  // namespace __1
[[noreturn]] void __throw_bad_alloc() { stwo_guest_abort("bad_alloc"); }
[[noreturn]] void terminate() noexcept { stwo_guest_abort("terminate"); }
const nothrow_t nothrow{};
}  // namespace std

// Never-used iostream objects referenced by dead tracer paths in evmone's
// vm.cpp (std::clog) and ziskethone's evmc2_evmone.cpp (std::cerr).
alignas(16) char stwo_dummy_clog[512] asm("_ZNSt3__14clogE");
alignas(16) char stwo_dummy_cerr[512] asm("_ZNSt3__14cerrE");

void* operator new(size_t n) { return heap_alloc(n); }
void* operator new[](size_t n) { return heap_alloc(n); }
void* operator new(size_t n, std::align_val_t a) { return aligned_alloc(static_cast<size_t>(a), n); }
void* operator new[](size_t n, std::align_val_t a) { return aligned_alloc(static_cast<size_t>(a), n); }
void* operator new(size_t n, const std::nothrow_t&) noexcept { return heap_alloc(n); }
void* operator new[](size_t n, const std::nothrow_t&) noexcept { return heap_alloc(n); }
void operator delete(void* p) noexcept { heap_free(p); }
void operator delete[](void* p) noexcept { heap_free(p); }
void operator delete(void* p, size_t) noexcept { heap_free(p); }
void operator delete[](void* p, size_t) noexcept { heap_free(p); }
void operator delete(void* p, std::align_val_t a) noexcept { if (size_t(a) <= 16) heap_free(p); }
void operator delete[](void* p, std::align_val_t a) noexcept { if (size_t(a) <= 16) heap_free(p); }
void operator delete(void* p, size_t, std::align_val_t a) noexcept { if (size_t(a) <= 16) heap_free(p); }
void operator delete[](void* p, size_t, std::align_val_t a) noexcept { if (size_t(a) <= 16) heap_free(p); }
