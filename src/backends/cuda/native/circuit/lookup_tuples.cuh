#pragma once
// Circuit LogUp fractions. The row and lookup order matches
// frontends/circuit/witness/components.zig; the shared relation completion
// kernel performs inversion, claimed sums and the circle-order prefix scan.
#include <cuda_runtime_api.h>
#include "../oods/field.cuh"

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::circuit_interaction {

namespace f = stwo::cuda::oods;
using M31 = f::M31;
using QM31 = f::QM31;

#if !defined(STWO_CIRCUIT_INTERACTION_HOST_EMULATION)
constexpr unsigned kThreads = 256;
#endif
constexpr unsigned kMaxPp = 11;
constexpr unsigned kMaxBase = 52;
constexpr unsigned kMaxInteraction = 52;
constexpr unsigned kComponents = 11;
constexpr unsigned kPpWidths[kComponents] = {2, 8, 5, 3, 11, 3, 0, 3, 3, 3, 1};
constexpr unsigned kBaseWidths[kComponents] = {4, 12, 20, 4, 52, 2, 16, 1, 1, 1, 1};
constexpr unsigned kSecure[kComponents] = {1, 2, 6, 3, 13, 1, 8, 1, 1, 1, 1};

// NVCC cannot address namespace-scope host constexpr arrays in device code.
// These template constants also let each component specialize its column load.
template <unsigned Kind>
__host__ __device__ constexpr unsigned pp_width() {
    if constexpr (Kind == 0) return 2;
    if constexpr (Kind == 1) return 8;
    if constexpr (Kind == 2) return 5;
    if constexpr (Kind == 3) return 3;
    if constexpr (Kind == 4) return 11;
    if constexpr (Kind == 5) return 3;
    if constexpr (Kind == 6) return 0;
    if constexpr (Kind == 7 || Kind == 8 || Kind == 9) return 3;
    return 1;
}

template <unsigned Kind>
__host__ __device__ constexpr unsigned base_width() {
    if constexpr (Kind == 0) return 4;
    if constexpr (Kind == 1) return 12;
    if constexpr (Kind == 2) return 20;
    if constexpr (Kind == 3) return 4;
    if constexpr (Kind == 4) return 52;
    if constexpr (Kind == 5) return 2;
    if constexpr (Kind == 6) return 16;
    return 1;
}

template <unsigned Kind>
__host__ __device__ constexpr unsigned lookup_count() {
    if constexpr (Kind == 0) return 2;
    if constexpr (Kind == 1) return 3;
    if constexpr (Kind == 2) return 12;
    if constexpr (Kind == 3) return 5;
    if constexpr (Kind == 4) return 26;
    if constexpr (Kind == 5) return 2;
    if constexpr (Kind == 6) return 16;
    return 1;
}

constexpr M31 kGate = 378353459u;
constexpr M31 kRc16 = 1008385708u;
constexpr M31 kXor4 = 45448144u;
constexpr M31 kXor7 = 62225763u;
constexpr M31 kXor8 = 112558620u;
constexpr M31 kXor8b = 521092554u;
constexpr M31 kXor9 = 95781001u;
constexpr M31 kXor12 = 648362599u;

struct Columns {
    const M31 *pp[kMaxPp];
    const M31 *base[kMaxBase];
    M31 *out[kMaxInteraction];
};

struct Lookup {
    M31 numerator;
    M31 tuple[6];
    unsigned len;
};

__host__ __device__ __forceinline__ Lookup use4(M31 id, M31 a, M31 b, M31 c) {
    return {1u, {id, a, b, c, 0u, 0u}, 4u};
}
__host__ __device__ __forceinline__ Lookup yield4(M31 multiplicity, M31 id, M31 a, M31 b, M31 c) {
    return {f::neg(multiplicity), {id, a, b, c, 0u, 0u}, 4u};
}
__host__ __device__ __forceinline__ Lookup gate6(M31 numerator, M31 address, const M31 *limbs) {
    return {numerator, {kGate, address, limbs[0], limbs[1], limbs[2], limbs[3]}, 6u};
}
__host__ __device__ __forceinline__ Lookup gate4(M31 numerator, M31 address, M31 lo, M31 hi) {
    return {numerator, {kGate, address, lo, hi, 0u, 0u}, 4u};
}
__host__ __device__ __forceinline__ M31 low(M31 value, M31 high, unsigned bits) {
    return f::sub(value, f::mul(high, 1u << bits));
}

template <unsigned Kind>
__host__ __device__ __forceinline__ Lookup lookup_at(
    unsigned index, unsigned row, const Columns &columns) {
    M31 c[kMaxBase] = {};
    M31 p[kMaxPp] = {};
    // The compiler prunes unused columns for every kind and lookup index.
    for (unsigned i = 0; i < base_width<Kind>(); ++i) c[i] = columns.base[i][row];
    for (unsigned i = 0; i < pp_width<Kind>(); ++i) p[i] = columns.pp[i][row];
    if constexpr (Kind == 0) {
        return gate6(1u, p[index], c);
    } else if constexpr (Kind == 1) {
        return gate6(index == 2 ? f::neg(p[7]) : 1u, p[4 + index], c + 4 * index);
    } else if constexpr (Kind == 2) {
        switch (index) {
            case 0: return use4(kXor8, low(c[0], c[8], 8), low(c[2], c[10], 8), c[16]);
            case 1: return use4(kXor8, c[8], c[10], c[17]);
            case 2: return use4(kXor8, low(c[1], c[9], 8), low(c[3], c[11], 8), c[18]);
            case 3: return use4(kXor8, c[9], c[11], c[19]);
            case 4: return use4(kXor8, c[16], low(c[4], c[12], 8), low(c[6], c[14], 8));
            case 5: return use4(kXor8, c[17], c[12], c[14]);
            case 6: return use4(kXor8, c[18], low(c[5], c[13], 8), low(c[7], c[15], 8));
            case 7: return use4(kXor8, c[19], c[13], c[15]);
            case 8: return gate4(1u, p[0], c[0], c[1]);
            case 9: return gate4(1u, p[1], c[2], c[3]);
            case 10: return gate4(1u, p[2], c[4], c[5]);
            default: return gate4(f::neg(p[4]), p[3], c[6], c[7]);
        }
    } else if constexpr (Kind == 3) {
        switch (index) {
            case 0: return {1u, {kRc16, c[1]}, 2u};
            case 1: return {1u, {kRc16, c[2]}, 2u};
            case 2: return {1u, {kRc16, f::sub(32767u, c[2])}, 2u};
            case 3: return {1u, {kGate, p[0], c[0]}, 3u};
            default: return {f::neg(p[2]), {kGate, p[1], c[1], c[2]}, 4u};
        }
    } else if constexpr (Kind == 4) {
        const M31 xr16_lo = f::add(c[28], f::mul(c[29], 256u));
        const M31 xr16_hi = f::add(c[26], f::mul(c[27], 256u));
        const M31 xr12_lo = f::add(c[37], f::mul(c[38], 16u));
        const M31 xr12_hi = f::add(c[39], f::mul(c[36], 16u));
        switch (index) {
            case 0: return use4(kXor8, low(c[20], c[22], 8), low(c[6], c[24], 8), c[26]);
            case 1: return use4(kXor8, c[22], c[24], c[27]);
            case 2: return use4(kXor8b, low(c[21], c[23], 8), low(c[7], c[25], 8), c[28]);
            case 3: return use4(kXor8b, c[23], c[25], c[29]);
            case 4: return use4(kXor12, low(c[2], c[32], 12), low(c[30], c[34], 12), c[36]);
            case 5: return use4(kXor4, c[32], c[34], c[37]);
            case 6: return use4(kXor12, low(c[3], c[33], 12), low(c[31], c[35], 12), c[38]);
            case 7: return use4(kXor4, c[33], c[35], c[39]);
            case 8: return use4(kXor8, c[40], c[42], low(c[18], c[44], 8));
            case 9: return use4(kXor8, low(c[13], c[41], 8), low(xr16_hi, c[43], 8), c[44]);
            case 10: return use4(kXor8, c[41], c[43], low(c[19], c[45], 8));
            case 11: return use4(kXor8, low(c[12], c[40], 8), low(xr16_lo, c[42], 8), c[45]);
            case 12: return use4(kXor9, c[46], c[48], low(c[14], c[50], 9));
            case 13: return use4(kXor7, low(xr12_hi, c[47], 7), low(c[17], c[49], 7), c[50]);
            case 14: return use4(kXor9, c[47], c[49], low(c[15], c[51], 9));
            case 15: return use4(kXor7, low(xr12_lo, c[46], 7), low(c[16], c[48], 7), c[51]);
            default: {
                const unsigned gate_index = index - 16u;
                const unsigned pair = gate_index < 6u ? gate_index : gate_index - 6u;
                const unsigned limb = gate_index < 6u ? gate_index : 6u + pair;
                return gate4(gate_index < 6u ? 1u : f::neg(p[10]),
                    p[limb], c[2u * limb], c[2u * limb + 1u]);
            }
        }
    } else if constexpr (Kind == 6) {
        const unsigned ah = index >> 2u, bh = index & 3u;
        const unsigned a = (ah << 10u) | (row >> 10u);
        const unsigned b = (bh << 10u) | (row & 1023u);
        return yield4(c[index], kXor12, a, b, a ^ b);
    } else if constexpr (Kind == 10) {
        return {f::neg(c[0]), {kRc16, p[0]}, 2u};
    } else {
        const M31 id = Kind == 5 ? (index == 0 ? kXor8 : kXor8b) :
            Kind == 7 ? kXor4 : Kind == 8 ? kXor7 : kXor9;
        return yield4(c[index], id, p[0], p[1], p[2]);
    }
}


} // namespace stwo::cuda::circuit_interaction
