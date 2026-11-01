// ECALL services of the stwo RV64 Ethereum guest ABI (our code).
//
// Admitted profile ethereum_services_v2 (autoresearch/guest_efficiency/CONTEXT.md):
//   0x0001_0001 Keccak-f[1600] in place on 25 little-endian u64 lanes
//   0x0002_0011 secp256k1 projective add, word packet (6 x 4 LE u64, 32-byte aligned)
//   0x0002_0012 secp256k1 projective double, word packet (3 x 4 LE u64)
// Candidate profile ethereum_services_v3_candidate (execution-only, -DCANDIDATE_SERVICES):
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

}  // namespace stwo
