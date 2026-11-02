/* Compile the same defined unsigned arithmetic natively and as RV64IM.
 * Volatile stack cells force real loads/stores and prevent constant folding.
 * RV64_GUEST has a diagnostic-only entry/exit contract; this is not an SP1 guest.
 */
typedef unsigned long long u64;
typedef unsigned int u32;
_Static_assert(sizeof(u64) == 8 && sizeof(u32) == 4, "integer widths");

static u64 compute(void) {
    volatile u64 cells[32];
    u64 a = 0x8123456789abcdefULL;
    u64 b = 0xfedcba9876543211ULL;
    for (u32 i = 0; i < 32; ++i) {
        a = (a ^ (b >> (i & 63))) * 0x9e3779b97f4a7c15ULL + i;
        b = (b << 7) | (b >> 57);
        cells[i] = a ^ (b / (a | 1)) ^ (b % (a | 1));
    }
    for (u32 i = 0; i < 32; ++i) {
        const u32 narrow = (u32)cells[i] + (u32)b;
        a = ((a << 13) | (a >> 51)) ^ cells[31 - i] ^ narrow;
        b += a;
    }
    return a ^ b;
}

#ifdef RV64_GUEST
__attribute__((noreturn)) void _start(void) {
    const u64 result = compute();
    __asm__ volatile("mv a0, %0\n\tebreak" : : "r"(result) : "a0", "memory");
    __builtin_unreachable();
}
#else
#include <stdio.h>
int main(void) {
    printf("%llu\n", compute());
    return 0;
}
#endif
