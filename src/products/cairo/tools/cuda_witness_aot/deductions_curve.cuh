// Canonical Cairo curve deductions, outside the immutable upstream closure.
static __device__ __forceinline__ bool stwo_wit_same_felt(
    const felt252& a, const felt252& b) {
    for (unsigned i = 0; i < 8; ++i)
        if (a.limbs[i] != b.limbs[i]) return false;
    return true;
}

static __device__ __forceinline__ void stwo_wit_ec_double(
    const AffinePointCuda& point, AffinePointCuda& out) {
    // alpha=1, slope=(3*x*x+1)/(2*y); inputs and outputs are canonical.
    felt252 x = felt_to_mont(point.x), y = felt_to_mont(point.y);
    felt252 xx = felt_mul(x, x);
    felt252 numerator = felt_add(felt_add(felt_add(xx, xx), xx),
        ff_dispatch_st<ff_config_starknet>::get_one());
    felt252 denominator = felt_add(y, y);
    unsigned nonzero = 0;
    for (unsigned i = 0; i < 8; ++i) nonzero |= denominator.limbs[i];
    if (nonzero == 0) { asm volatile("trap;"); return; }
    felt252 slope = felt_mul(numerator, felt_inverse(denominator));
    felt252 nx = felt_sub(felt_sub(felt_mul(slope, slope), x), x);
    out.x = felt_from_mont(nx);
    out.y = felt_from_mont(felt_sub(felt_mul(slope, felt_sub(x, nx)), y));
}

static __device__ __forceinline__ void stwo_wit_ec_add(
    const AffinePointCuda& a, const AffinePointCuda& b, AffinePointCuda& out) {
    if (!stwo_wit_same_felt(a.x, b.x)) { ec_add_affine(a, b, out); return; }
    if (!stwo_wit_same_felt(a.y, b.y)) { asm volatile("trap;"); return; }
    stwo_wit_ec_double(a, out);
}

#ifdef STWO_WIT_NEEDS_PEDERSEN
static __device__ __forceinline__ void stwo_wit_deduce_pedersen_points_w9(
    const unsigned* in, unsigned* out) {
    // W9 must never accidentally use the old W18 table under the same globals.
    if (g_stwo_wit_pedersen_n_rows != 32768u) { asm volatile("trap;"); return; }
    unsigned row = in[0] & 65535u;
    for (unsigned c = 0; c < 56; ++c) out[c] = g_stwo_wit_pedersen_cols[c][row];
}

static __device__ __forceinline__ void stwo_wit_deduce_partial_ec_mul_w9(
    const unsigned* in, unsigned* out) {
    unsigned index[1] = {in[1] * 512u + in[2]};
    unsigned limbs[56];
    stwo_wit_deduce_pedersen_points_w9(index, limbs);
    AffinePointCuda acc, point, sum;
    felt252_from_m31_limbs(acc.x, in + 30);
    felt252_from_m31_limbs(acc.y, in + 58);
    felt252_from_m31_limbs(point.x, limbs);
    felt252_from_m31_limbs(point.y, limbs + 28);
    stwo_wit_ec_add(acc, point, sum);
    out[0] = in[0]; out[1] = in[1] + 1u;
    for (unsigned i = 0; i < 27; ++i) out[2 + i] = in[3 + i];
    out[29] = 0;
    felt252_to_m31_limbs(sum.x, out + 30);
    felt252_to_m31_limbs(sum.y, out + 58);
}
#endif

static __device__ __forceinline__ void stwo_wit_deduce_partial_ec_mul_generic(
    const unsigned* in, unsigned* out) {
    AffinePointCuda point, acc, doubled, sum;
    felt252_from_m31_limbs(point.x, in + 12);
    felt252_from_m31_limbs(point.y, in + 40);
    felt252_from_m31_limbs(acc.x, in + 68);
    felt252_from_m31_limbs(acc.y, in + 96);
    out[0] = in[0]; out[1] = in[1] == 2147483646u ? 0u : in[1] + 1u;
    if (in[124] == 0) {
        for (unsigned i = 0; i < 9; ++i) out[2 + i] = in[3 + i];
        out[11] = 0;
    } else {
        out[2] = in[2] >> 1;
        for (unsigned i = 1; i < 10; ++i) out[2 + i] = in[2 + i];
    }
    stwo_wit_ec_double(point, doubled);
    felt252_to_m31_limbs(doubled.x, out + 12);
    felt252_to_m31_limbs(doubled.y, out + 40);
    if (in[2] & 1u) { stwo_wit_ec_add(acc, point, sum); acc = sum; }
    felt252_to_m31_limbs(acc.x, out + 68);
    felt252_to_m31_limbs(acc.y, out + 96);
    out[124] = in[124] == 0 ? 26u : in[124] - 1u;
}
