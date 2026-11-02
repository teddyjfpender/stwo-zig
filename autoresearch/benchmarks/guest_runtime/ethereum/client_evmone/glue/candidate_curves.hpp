// Execution-only candidate curve, field and sponge services (our code).
//
// Profile ethereum_services_v3_candidate; ABI in
// autoresearch/guest_efficiency/notes/candidate-curves-abi.md. Every packet
// word is a pointer to an 8-byte aligned operand (little-endian u64 limbs),
// except the sponge's length and flags. All registers are preserved.
//
//   0x0003_0100 bn254_g1_add      {r, p, q}  affine r = p + q, x_p != x_q
//   0x0003_0101 bn254_g1_double   {r, p}     affine r = 2p, y_p != 0
//   0x0003_0102 bn254_fp2_mul     {r, a, b}  r = a * b in Fp[u]/(u^2+1), plain form
//   0x0003_0110 bls12_381_g1_add  {r, p, q}  as bn254, Montgomery residues (blst form)
//   0x0003_0111 bls12_381_g1_double {r, p}
//   0x0003_0112 bls12_381_fp2_mul {r, a, b}  r = a * b * 2^-384 per coefficient
//   0x0003_0120 arith384_mod      {a, b, c, m, r}  r = (a*b + c) mod m
//   0x0003_0121 arith384_mont     {a, b, m, r}     r = a*b*2^-384 mod m, m odd
//   0x0003_0130 keccak_sponge     {state, in, len, flags}  Keccak-256 rate 136;
//               flags bit0 = finalize (pad 0x01..0x80), bit1 = fresh (zero state)
#pragma once
#include <cstdint>

#include "services.hpp"

namespace stwo {

inline constexpr uint64_t kCandBn254G1Add = 0x00030100;
inline constexpr uint64_t kCandBn254G1Double = 0x00030101;
inline constexpr uint64_t kCandBn254Fp2Mul = 0x00030102;
inline constexpr uint64_t kCandBls12381G1Add = 0x00030110;
inline constexpr uint64_t kCandBls12381G1Double = 0x00030111;
inline constexpr uint64_t kCandBls12381Fp2Mul = 0x00030112;
inline constexpr uint64_t kCandArith384Mod = 0x00030120;
inline constexpr uint64_t kCandArith384Mont = 0x00030121;
inline constexpr uint64_t kCandKeccakSponge = 0x00030130;
inline constexpr uint64_t kSpongeFinalize = 1;
inline constexpr uint64_t kSpongeFresh = 2;

inline uint64_t ptr(const void* p) noexcept { return reinterpret_cast<uint64_t>(p); }

inline void cand3(uint64_t tag, const void* a, const void* b, const void* c) noexcept {
    alignas(8) uint64_t pk[3] = {ptr(a), ptr(b), ptr(c)};
    ecall(tag, pk);
}
inline void cand2(uint64_t tag, const void* a, const void* b) noexcept {
    alignas(8) uint64_t pk[2] = {ptr(a), ptr(b)};
    ecall(tag, pk);
}
inline void cand4(uint64_t tag, const void* a, const void* b, const void* c, const void* d) noexcept {
    alignas(8) uint64_t pk[4] = {ptr(a), ptr(b), ptr(c), ptr(d)};
    ecall(tag, pk);
}

// One call hashes `n` bytes into the first four lanes of `st` (25 lanes).
inline void cand_keccak256(uint64_t st[25], const void* data, uint64_t n) noexcept {
    alignas(8) uint64_t pk[4] = {ptr(st), ptr(data), n, kSpongeFinalize | kSpongeFresh};
    ecall(kCandKeccakSponge, pk);
}

}  // namespace stwo
