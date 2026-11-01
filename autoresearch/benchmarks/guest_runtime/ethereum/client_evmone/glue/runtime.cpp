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

#include "services.hpp"
#include "mem_functions.hpp"

// Candidate profile: bulk copies/fills/compares at or above this size go to the
// execution-only memory services (CONTEXT.md); smaller ones stay software.
#if defined(CANDIDATE_MEM)
static constexpr size_t kCandMemMin = 32;
#endif

// Admitted v3 bulk memory (ethereum_services_v3, ADMITTED_MEM): 8-aligned packet,
// dst (memcmp: a and b) 8-aligned, memcpy src of any alignment, len a nonzero
// multiple of 8 and at most 1 MiB, packet/src/dst words pairwise disjoint. As in
// the Rust guest's `admitted-mem` feature (ethereum/rv64/mem), the destination's
// unaligned head and tail are copied inline (a memcmp tail compared inline),
// bodies are split into 1 MiB chunks, and overlapping moves, unaligned memcmp
// operands and calls below the thresholds stay in software, so a wrapper call
// never traps.
#if defined(ADMITTED_MEM)
#if !defined(STWO_ADMITTED_COPY_MIN)
#define STWO_ADMITTED_COPY_MIN 64
#endif
#if !defined(STWO_ADMITTED_UCOPY_MIN)
#define STWO_ADMITTED_UCOPY_MIN 16
#endif
#if !defined(STWO_ADMITTED_SET_MIN)
#define STWO_ADMITTED_SET_MIN 64
#endif
#if !defined(STWO_ADMITTED_CMP_MIN)
#define STWO_ADMITTED_CMP_MIN 8
#endif
namespace {
constexpr size_t kAdmittedMax = size_t(1) << 20;
inline void v3_bulk(uint64_t tag, uint64_t d, uint64_t w1, uint64_t n) noexcept {
    alignas(8) uint64_t p[3] = {d, w1, n};
    stwo::ecall(tag, p);
}
inline void v3_copy_words(uint8_t* d, const uint8_t* s, size_t n) noexcept {
    while (n > kAdmittedMax) {
        v3_bulk(stwo::kV3Memcpy, reinterpret_cast<uint64_t>(d), reinterpret_cast<uint64_t>(s), kAdmittedMax);
        d += kAdmittedMax; s += kAdmittedMax; n -= kAdmittedMax;
    }
    v3_bulk(stwo::kV3Memcpy, reinterpret_cast<uint64_t>(d), reinterpret_cast<uint64_t>(s), n);
}
inline void v3_fill_words(uint8_t* d, uint8_t byte, size_t n) noexcept {
    while (n > kAdmittedMax) {
        v3_bulk(stwo::kV3Memset, reinterpret_cast<uint64_t>(d), byte, kAdmittedMax);
        d += kAdmittedMax; n -= kAdmittedMax;
    }
    v3_bulk(stwo::kV3Memset, reinterpret_cast<uint64_t>(d), byte, n);
}
static_assert(STWO_ADMITTED_COPY_MIN >= 15 && STWO_ADMITTED_UCOPY_MIN >= 15 && STWO_ADMITTED_SET_MIN >= 15,
              "thresholds below 15 bytes may leave no whole destination word");
// Service copy/fill of n >= 15 bytes (split_copy/split_fill in
// mem_functions.hpp). Byte-disjoint ranges never share a service word: the
// destination body is word-aligned.
__attribute__((noinline)) void v3_copy_run(uint8_t* dp, const uint8_t* sp, size_t n) noexcept {
    split_copy(dp, sp, n, [](uint8_t* d, const uint8_t* s, size_t len) { v3_copy_words(d, s, len); });
}
__attribute__((noinline)) void v3_set_run(uint8_t* dp, int c, size_t n) noexcept {
    split_fill(dp, c, n, [](uint8_t* d, uint8_t byte, size_t len) { v3_fill_words(d, byte, len); });
}
// Returns false (caller copies in software) for overlapping ranges or calls
// below the threshold.
__attribute__((always_inline)) inline bool v3_copy(void* dst, const void* src, size_t n) noexcept {
    const uintptr_t d = reinterpret_cast<uintptr_t>(dst), s = reinterpret_cast<uintptr_t>(src);
#if defined(ADMITTED_UMEM)
    // UNVERIFIED (bulk-unaligned track): unaligned-source memcpy is not yet
    // proved by the bulk-memory AIR; opt in with --v3-set ...,umem.
    const size_t min = ((d ^ s) & 7) == 0 ? STWO_ADMITTED_COPY_MIN : STWO_ADMITTED_UCOPY_MIN;
#else
    if (((d ^ s) & 7) != 0) return false;
    const size_t min = STWO_ADMITTED_COPY_MIN;
#endif
    if (n < min || (d < s + n && s < d + n)) return false;
    v3_copy_run(static_cast<uint8_t*>(dst), static_cast<const uint8_t*>(src), n);
    return true;
}
__attribute__((always_inline)) inline bool v3_set(void* dst, int c, size_t n) noexcept {
    if (n < STWO_ADMITTED_SET_MIN) return false;
    v3_set_run(static_cast<uint8_t*>(dst), c, n);
    return true;
}
// memcmp body through the service when a and b are 8-aligned and disjoint;
// returns false (caller compares in software) otherwise.
inline bool v3_compare(const void* a, const void* b, size_t n, int* out) noexcept {
    const uintptr_t x = reinterpret_cast<uintptr_t>(a), y = reinterpret_cast<uintptr_t>(b);
    if (n < STWO_ADMITTED_CMP_MIN || n < 8 || ((x | y) & 7) != 0 || (x < y + n && y < x + n)) return false;
    const uint8_t* pa = static_cast<const uint8_t*>(a);
    const uint8_t* pb = static_cast<const uint8_t*>(b);
    size_t body = n & ~size_t(7);
    while (body != 0) {
        const size_t chunk = body > kAdmittedMax ? kAdmittedMax : body;
        alignas(8) uint64_t p[4] = {reinterpret_cast<uint64_t>(pa), reinterpret_cast<uint64_t>(pb), chunk, 0};
        stwo::ecall(stwo::kV3Memcmp, p);
        if (p[3] != 0) { *out = static_cast<int>(static_cast<int64_t>(p[3])); return true; }
        pa += chunk; pb += chunk; body -= chunk;
    }
    for (size_t i = 0; i < (n & 7); ++i)
        if (pa[i] != pb[i]) { *out = int(pa[i]) - int(pb[i]); return true; }
    *out = 0;
    return true;
}
}  // namespace
#endif

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

// ----- memory functions (implementations in mem_functions.hpp) -----------

void* memcpy(void* dst, const void* src, size_t n) {
#if defined(ADMITTED_MEM)
    if (v3_copy(dst, src, n)) return dst;
#endif
#if defined(CANDIDATE_MEM)
    if (n >= kCandMemMin) { stwo::cand_memcpy(dst, src, n); return dst; }
#endif
    return stwo_memcpy(dst, src, n);
}
void* memmove(void* dst, const void* src, size_t n) {
#if defined(ADMITTED_MEM)
    if (v3_copy(dst, src, n)) return dst;  // disjoint ranges only; overlap stays in software
#endif
#if defined(CANDIDATE_MEM)
    if (n >= kCandMemMin) { stwo::cand_memcpy(dst, src, n); return dst; }  // memmove-safe
#endif
    return stwo_memmove(dst, src, n);
}
void* memset(void* dst, int c, size_t n) {
#if defined(ADMITTED_MEM)
    if (v3_set(dst, c, n)) return dst;
#endif
#if defined(CANDIDATE_MEM)
    if (n >= kCandMemMin) { stwo::cand_memset(dst, c, n); return dst; }
#endif
    return stwo_memset(dst, c, n);
}
int memcmp(const void* a, const void* b, size_t n) {
#if defined(ADMITTED_UMEM)
    // UNVERIFIED (bulk-unaligned track): the Word16 services collector does
    // not yet accept memcmp (0x0003_0003); opt in with --v3-set ...,umem.
    int r;
    if (v3_compare(a, b, n, &r)) return r;
#endif
#if defined(CANDIDATE_MEM)
    if (n >= kCandMemMin) return stwo::cand_memcmp(a, b, n);
#endif
    return stwo_memcmp(a, b, n);
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
