// ECALL services of the stwo RV64 Ethereum guest ABI (our code).
//
// Admitted profile ethereum_services_v2 (autoresearch/guest_efficiency/CONTEXT.md):
//   0x0001_0001 Keccak-f[1600] in place on 25 little-endian u64 lanes
//   0x0002_0011 secp256k1 projective add, word packet (6 x 4 LE u64, 32-byte aligned)
//   0x0002_0012 secp256k1 projective double, word packet (3 x 4 LE u64)
// Candidate profile ethereum_services_v3_candidate (execution-only; build.py --profile candidate
// defines CANDIDATE_SERVICES plus CANDIDATE_MEM / CANDIDATE_SHA / CANDIDATE_ARITH per --candidate-set):
//   0x0003_0001 memcpy, 0x0003_0002 memset, 0x0003_0003 memcmp,
//   0x0003_0010 sha256_compress, 0x0003_0020 arith256, 0x0003_0021 arith256_mod
// All registers are preserved; only the packet changes.
//
// Host builds (STWO_HOST) emulate every service in software so the same glue
// can be debugged natively.
#pragma once
#include <cstddef>
#include <cstdint>

namespace stwo {

inline constexpr uint64_t kKeccakF = 0x00010001;
inline constexpr uint64_t kSecpAddWords = 0x00020011;
inline constexpr uint64_t kSecpDoubleWords = 0x00020012;
inline constexpr uint64_t kCandMemcpy = 0x00030001;
inline constexpr uint64_t kCandMemset = 0x00030002;
inline constexpr uint64_t kCandMemcmp = 0x00030003;
inline constexpr uint64_t kCandSha256 = 0x00030010;
inline constexpr uint64_t kCandArith256 = 0x00030020;
inline constexpr uint64_t kCandArith256Mod = 0x00030021;

#if defined(STWO_HOST)
void host_service(uint64_t tag, void* packet) noexcept;
inline void ecall(uint64_t tag, void* packet) noexcept { host_service(tag, packet); }
#else
inline void ecall(uint64_t tag, void* packet) noexcept {
    register void* a0 asm("a0") = packet;
    register uint64_t a7 asm("a7") = tag;
    asm volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}
#endif

inline void keccak_f(uint64_t* state25) noexcept { ecall(kKeccakF, state25); }

struct alignas(32) SecpAddPacket { uint64_t w[24]; };
struct alignas(32) SecpDoublePacket { uint64_t w[12]; };
inline void secp_add(SecpAddPacket& p) noexcept { ecall(kSecpAddWords, p.w); }
inline void secp_double(SecpDoublePacket& p) noexcept { ecall(kSecpDoubleWords, p.w); }

#if defined(CANDIDATE_SERVICES)
// Execution-only candidate services (profile ethereum_services_v3_candidate).
inline void cand_memcpy(void* d, const void* src, size_t n) noexcept {
    alignas(8) uint64_t p[3] = {reinterpret_cast<uint64_t>(d), reinterpret_cast<uint64_t>(src), n};
    ecall(kCandMemcpy, p);
}
inline void cand_memset(void* d, int c, size_t n) noexcept {
    alignas(8) uint64_t p[3] = {reinterpret_cast<uint64_t>(d), uint64_t(c & 0xff), n};
    ecall(kCandMemset, p);
}
inline int cand_memcmp(const void* a, const void* b, size_t n) noexcept {
    alignas(8) uint64_t p[4] = {reinterpret_cast<uint64_t>(a), reinterpret_cast<uint64_t>(b), n, 0};
    ecall(kCandMemcmp, p);
    return static_cast<int>(static_cast<int64_t>(p[3]));
}
#endif
}  // namespace stwo

// r = (a*b + c) mod m on 4 little-endian u64 limbs (candidate arith256_mod;
// m == 0 gives 0). Implemented in glue/arith_stwo.cpp.
extern "C" void stwo_arith256_mod(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                                  const uint64_t m[4], uint64_t r[4]) noexcept;
