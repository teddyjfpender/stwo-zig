/* Force-included by `build.py --isa zbb_binary` (profile ethereum_services_v3_zbb).
 *
 * LLVM cannot enable a subset of Zbb: `+zbb` also emits clz/ctz/cpop/min/max/
 * rotates/orc.b, and `+zbkb` emits pack/packh and rotates, none of which the
 * prover admits. So the compiler targets plain RV64IM and the one admitted op
 * that carries the measured Zbb saving, rev8, is issued explicitly here as a
 * raw `.insn` (the assembler is not told about Zbb either). build.py then audits
 * the linked ELF with rv64-isa-audit --require-subset: only RV64IM plus the
 * admitted Zbb BINARY encodings may appear.
 *
 * Every __builtin_bswap{16,32,64} in the client becomes rev8 (+ srli for the
 * narrow forms) at run time; constant evaluation keeps the portable expression.
 */
#if !defined(STWO_ZBB_BINARY_H) && !defined(__ASSEMBLER__)
#define STWO_ZBB_BINARY_H
#include <stdint.h>

static inline __attribute__((always_inline)) uint64_t stwo_zbb_rev8_rt(uint64_t x) {
    uint64_t r;
    /* rev8 rd, rs1 (RV64): OP-IMM, funct3 101, imm12 0x6b8. */
    __asm__(".insn i 0x13, 5, %0, %1, 0x6b8" : "=r"(r) : "r"(x));
    return r;
}

#ifdef __cplusplus
constexpr inline uint64_t stwo_zbb_rev8_ce(uint64_t x) {
    x = (x << 32) | (x >> 32);
    x = ((x & 0x0000FFFF0000FFFFull) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFull);
    x = ((x & 0x00FF00FF00FF00FFull) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFull);
    return x;
}
[[gnu::always_inline]] constexpr inline uint64_t stwo_zbb_rev8(uint64_t x) {
    if (__builtin_is_constant_evaluated()) return stwo_zbb_rev8_ce(x);
    return stwo_zbb_rev8_rt(x);
}
[[gnu::always_inline]] constexpr inline uint32_t stwo_zbb_bswap32(uint32_t x) {
    return static_cast<uint32_t>(stwo_zbb_rev8(x) >> 32);
}
[[gnu::always_inline]] constexpr inline uint16_t stwo_zbb_bswap16(uint16_t x) {
    return static_cast<uint16_t>(stwo_zbb_rev8(x) >> 48);
}
#else
#define stwo_zbb_rev8(x) stwo_zbb_rev8_rt(x)
static inline __attribute__((always_inline)) uint32_t stwo_zbb_bswap32(uint32_t x) {
    return (uint32_t)(stwo_zbb_rev8_rt(x) >> 32);
}
static inline __attribute__((always_inline)) uint16_t stwo_zbb_bswap16(uint16_t x) {
    return (uint16_t)(stwo_zbb_rev8_rt(x) >> 48);
}
#endif

#ifdef STWO_ZBB_BINARY_BUILTINS
#define __builtin_bswap64(x) stwo_zbb_rev8(x)
#define __builtin_bswap32(x) stwo_zbb_bswap32(x)
#define __builtin_bswap16(x) stwo_zbb_bswap16(x)
#endif

#endif
