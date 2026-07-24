typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

#ifndef STWO_M31_FAST32_GLOBAL
#define STWO_M31_FAST32_GLOBAL 0
#endif
#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
#error "STWO_M31_FAST32_GLOBAL must be 0 or 1"
#endif

__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
    unsigned sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}

__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    unsigned negated = STWO_M31_P - value;
    return negated == STWO_M31_P ? 0u : negated;
}

__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
#if STWO_M31_FAST32_GLOBAL
    unsigned lo = lhs * rhs;
    unsigned hi = __umulhi(lhs, rhs);
    unsigned quotient = (hi << 1) | (lo >> 31);
    unsigned reduced = (lo & STWO_M31_P) + quotient;
    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
    return reduced == STWO_M31_P ? 0u : reduced;
#else
    u64 product = (u64)lhs * (u64)rhs;
    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

__device__ __forceinline__ unsigned stwo_m31_square(unsigned value) {
    return stwo_m31_mul(value, value);
}

__device__ __forceinline__ unsigned stwo_m31_pow2k(unsigned squarings, unsigned value) {
    unsigned result = value;
    for (unsigned i = 0; i < squarings; ++i) { result = stwo_m31_square(result); }
    return result;
}

__device__ __forceinline__ unsigned stwo_m31_inv(unsigned value) {
    unsigned t0 = stwo_m31_mul(stwo_m31_pow2k(2u, value), value);
    unsigned t1 = stwo_m31_mul(stwo_m31_pow2k(1u, t0), t0);
    unsigned t2 = stwo_m31_mul(stwo_m31_pow2k(3u, t1), t0);
    unsigned t3 = stwo_m31_mul(stwo_m31_pow2k(1u, t2), t0);
    unsigned t4 = stwo_m31_mul(stwo_m31_pow2k(8u, t3), t3);
    unsigned t5 = stwo_m31_mul(stwo_m31_pow2k(8u, t4), t3);
    return stwo_m31_mul(stwo_m31_pow2k(7u, t5), t2);
}

struct StwoCudaQm31 { unsigned a, b, c, d; };

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_add(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_add(l.a, r.a), stwo_m31_add(l.b, r.b),
                        stwo_m31_add(l.c, r.c), stwo_m31_add(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_sub(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_sub(l.a, r.a), stwo_m31_sub(l.b, r.b),
                        stwo_m31_sub(l.c, r.c), stwo_m31_sub(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul_base(StwoCudaQm31 v, unsigned s) {
    return StwoCudaQm31{stwo_m31_mul(v.a, s), stwo_m31_mul(v.b, s),
                        stwo_m31_mul(v.c, s), stwo_m31_mul(v.d, s)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul(StwoCudaQm31 l, StwoCudaQm31 r) {
    unsigned a0 = l.a, a1 = l.b, a2 = l.c, a3 = l.d;
    unsigned b0 = r.a, b1 = r.b, b2 = r.c, b3 = r.d;
    unsigned x0 = stwo_m31_sub(stwo_m31_mul(a0, b0), stwo_m31_mul(a1, b1));
    unsigned x1 = stwo_m31_add(stwo_m31_mul(a0, b1), stwo_m31_mul(a1, b0));
    unsigned y0 = stwo_m31_sub(stwo_m31_mul(a2, b2), stwo_m31_mul(a3, b3));
    unsigned y1 = stwo_m31_add(stwo_m31_mul(a2, b3), stwo_m31_mul(a3, b2));
    unsigned c0 = stwo_m31_sub(stwo_m31_mul(a0, b2), stwo_m31_mul(a1, b3));
    unsigned c1 = stwo_m31_add(stwo_m31_mul(a0, b3), stwo_m31_mul(a1, b2));
    unsigned c2 = stwo_m31_sub(stwo_m31_mul(a2, b0), stwo_m31_mul(a3, b1));
    unsigned c3 = stwo_m31_add(stwo_m31_mul(a2, b1), stwo_m31_mul(a3, b0));
    unsigned ry0 = stwo_m31_sub(stwo_m31_mul(2u, y0), y1);
    unsigned ry1 = stwo_m31_add(y0, stwo_m31_mul(2u, y1));
    return StwoCudaQm31{stwo_m31_add(x0, ry0), stwo_m31_add(x1, ry1),
                        stwo_m31_add(c0, c2), stwo_m31_add(c1, c3)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_load_qm31(const unsigned *values, unsigned index) {
    unsigned base = index * 4u;
    return StwoCudaQm31{values[base], values[base + 1u], values[base + 2u], values[base + 3u]};
}

__device__ __forceinline__ unsigned stwo_bit_reverse(unsigned index, unsigned bits) {
    return __brev(index) >> (32u - bits);
}

__device__ __forceinline__ unsigned stwo_offset_bit_reversed_circle_domain_index(
    unsigned i, unsigned domain_log_size, unsigned eval_log_size, int offset
) {
    unsigned prev = stwo_bit_reverse(i, eval_log_size);
    unsigned half_size = 1u << (eval_log_size - 1u);
    int step = offset * (int)(1u << (eval_log_size - domain_log_size - 1u));
    if (prev < half_size) {
        int p = ((int)prev + step) % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p;
    } else {
        int p = (int)prev - step;
        p = p % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p + half_size;
    }
    return stwo_bit_reverse(prev, eval_log_size);
}

__device__ __forceinline__ unsigned stwo_trace_value(
    const unsigned *const *trace_cols, const unsigned *interaction_offsets, unsigned row_count,
    unsigned log_n_rows, unsigned interaction, unsigned column, unsigned row_index, int offset
) {
    unsigned target_row;
    if (offset == 0) {
        target_row = row_index;
    } else {
        unsigned eval_log_size = 0u;
        unsigned tmp = row_count;
        while (tmp > 1u) { tmp >>= 1u; eval_log_size++; }
        target_row = stwo_offset_bit_reversed_circle_domain_index(
            row_index, log_n_rows, eval_log_size, offset);
    }
    unsigned global_column = interaction_offsets[interaction] + column;
    return trace_cols[global_column][target_row];
}

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_748b232fa7601f20(
    const unsigned *const *trace_cols,
    const unsigned *interaction_offsets,
    const unsigned *base_params,
    const unsigned *ext_params,
    const unsigned *random_coeff_powers,
    const unsigned *denom_inv,
    unsigned *coord_0,
    unsigned *coord_1,
    unsigned *coord_2,
    unsigned *coord_3,
    unsigned row_count,
    unsigned log_n_rows,
    unsigned rc_base
) {
    unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_index >= row_count) { return; }

    // Canonical ext stream with demand-driven, versioned base cones.
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 388u, row_index, 0);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 387u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    unsigned b556 = base_params[319u];
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 359u, row_index, 0);
    unsigned b553 = base_params[306u];
    unsigned b554 = stwo_m31_mul(b180, b553);
    unsigned b555 = stwo_m31_sub(b106, b554);
    unsigned b557 = stwo_m31_mul(b556, b555);
    unsigned b558 = stwo_m31_add(b105, b557);
    unsigned b753 = stwo_m31_sub(b181, b558);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 309u, row_index, 0);
    unsigned b364 = base_params[190u];
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 310u, row_index, 0);
    unsigned b325 = base_params[177u];
    unsigned b326 = stwo_m31_mul(b154, b325);
    unsigned b327 = stwo_m31_sub(b48, b326);
    unsigned b365 = stwo_m31_mul(b364, b327);
    unsigned b366 = stwo_m31_add(b153, b365);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 333u, row_index, 0);
    unsigned b505 = base_params[248u];
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b506 = stwo_m31_mul(b505, b91);
    unsigned b507 = stwo_m31_add(b173, b506);
    unsigned b574 = stwo_m31_mul(b366, b507);
    unsigned b367 = base_params[191u];
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b368 = stwo_m31_mul(b367, b49);
    unsigned b369 = stwo_m31_add(b154, b368);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b502 = base_params[247u];
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b457 = base_params[232u];
    unsigned b458 = stwo_m31_mul(b173, b457);
    unsigned b459 = stwo_m31_sub(b90, b458);
    unsigned b503 = stwo_m31_mul(b502, b459);
    unsigned b504 = stwo_m31_add(b89, b503);
    unsigned b575 = stwo_m31_mul(b369, b504);
    unsigned b576 = stwo_m31_add(b574, b575);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b370 = base_params[192u];
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 311u, row_index, 0);
    unsigned b328 = base_params[178u];
    unsigned b329 = stwo_m31_mul(b155, b328);
    unsigned b330 = stwo_m31_sub(b51, b329);
    unsigned b371 = stwo_m31_mul(b370, b330);
    unsigned b372 = stwo_m31_add(b50, b371);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 332u, row_index, 0);
    unsigned b499 = base_params[246u];
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b500 = stwo_m31_mul(b499, b88);
    unsigned b501 = stwo_m31_add(b172, b500);
    unsigned b577 = stwo_m31_mul(b372, b501);
    unsigned b578 = stwo_m31_add(b576, b577);
    unsigned b373 = base_params[193u];
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 312u, row_index, 0);
    unsigned b331 = base_params[179u];
    unsigned b332 = stwo_m31_mul(b156, b331);
    unsigned b333 = stwo_m31_sub(b52, b332);
    unsigned b374 = stwo_m31_mul(b373, b333);
    unsigned b375 = stwo_m31_add(b155, b374);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 331u, row_index, 0);
    unsigned b496 = base_params[245u];
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b454 = base_params[231u];
    unsigned b455 = stwo_m31_mul(b172, b454);
    unsigned b456 = stwo_m31_sub(b87, b455);
    unsigned b497 = stwo_m31_mul(b496, b456);
    unsigned b498 = stwo_m31_add(b171, b497);
    unsigned b579 = stwo_m31_mul(b375, b498);
    unsigned b580 = stwo_m31_add(b578, b579);
    unsigned b376 = base_params[194u];
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b377 = stwo_m31_mul(b376, b53);
    unsigned b378 = stwo_m31_add(b156, b377);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b493 = base_params[244u];
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b451 = base_params[230u];
    unsigned b452 = stwo_m31_mul(b171, b451);
    unsigned b453 = stwo_m31_sub(b86, b452);
    unsigned b494 = stwo_m31_mul(b493, b453);
    unsigned b495 = stwo_m31_add(b85, b494);
    unsigned b581 = stwo_m31_mul(b378, b495);
    unsigned b582 = stwo_m31_add(b580, b581);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b379 = base_params[195u];
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 313u, row_index, 0);
    unsigned b334 = base_params[180u];
    unsigned b335 = stwo_m31_mul(b157, b334);
    unsigned b336 = stwo_m31_sub(b55, b335);
    unsigned b380 = stwo_m31_mul(b379, b336);
    unsigned b381 = stwo_m31_add(b54, b380);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 330u, row_index, 0);
    unsigned b490 = base_params[243u];
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b491 = stwo_m31_mul(b490, b84);
    unsigned b492 = stwo_m31_add(b170, b491);
    unsigned b583 = stwo_m31_mul(b381, b492);
    unsigned b584 = stwo_m31_add(b582, b583);
    unsigned b382 = base_params[196u];
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b383 = stwo_m31_mul(b382, b56);
    unsigned b384 = stwo_m31_add(b157, b383);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 329u, row_index, 0);
    unsigned b487 = base_params[242u];
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b448 = base_params[229u];
    unsigned b449 = stwo_m31_mul(b170, b448);
    unsigned b450 = stwo_m31_sub(b83, b449);
    unsigned b488 = stwo_m31_mul(b487, b450);
    unsigned b489 = stwo_m31_add(b169, b488);
    unsigned b585 = stwo_m31_mul(b384, b489);
    unsigned b586 = stwo_m31_add(b584, b585);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 304u, row_index, 0);
    unsigned b340 = base_params[182u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 305u, row_index, 0);
    unsigned b310 = base_params[172u];
    unsigned b311 = stwo_m31_mul(b149, b310);
    unsigned b312 = stwo_m31_sub(b37, b311);
    unsigned b341 = stwo_m31_mul(b340, b312);
    unsigned b342 = stwo_m31_add(b148, b341);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 314u, row_index, 0);
    unsigned b406 = base_params[208u];
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 315u, row_index, 0);
    unsigned b388 = base_params[198u];
    unsigned b389 = stwo_m31_mul(b159, b388);
    unsigned b390 = stwo_m31_sub(b59, b389);
    unsigned b407 = stwo_m31_mul(b406, b390);
    unsigned b408 = stwo_m31_add(b158, b407);
    unsigned b615 = stwo_m31_add(b342, b408);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 328u, row_index, 0);
    unsigned b481 = base_params[240u];
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b482 = stwo_m31_mul(b481, b80);
    unsigned b483 = stwo_m31_add(b168, b482);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 338u, row_index, 0);
    unsigned b547 = base_params[266u];
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    unsigned b548 = stwo_m31_mul(b547, b102);
    unsigned b549 = stwo_m31_add(b178, b548);
    unsigned b630 = stwo_m31_add(b483, b549);
    unsigned b633 = stwo_m31_mul(b615, b630);
    unsigned b343 = base_params[183u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b344 = stwo_m31_mul(b343, b38);
    unsigned b345 = stwo_m31_add(b149, b344);
    unsigned b409 = base_params[209u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b410 = stwo_m31_mul(b409, b60);
    unsigned b411 = stwo_m31_add(b159, b410);
    unsigned b616 = stwo_m31_add(b345, b411);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b478 = base_params[239u];
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b442 = base_params[227u];
    unsigned b443 = stwo_m31_mul(b168, b442);
    unsigned b444 = stwo_m31_sub(b79, b443);
    unsigned b479 = stwo_m31_mul(b478, b444);
    unsigned b480 = stwo_m31_add(b78, b479);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    unsigned b544 = base_params[265u];
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b520 = base_params[253u];
    unsigned b521 = stwo_m31_mul(b178, b520);
    unsigned b522 = stwo_m31_sub(b101, b521);
    unsigned b545 = stwo_m31_mul(b544, b522);
    unsigned b546 = stwo_m31_add(b100, b545);
    unsigned b629 = stwo_m31_add(b480, b546);
    unsigned b634 = stwo_m31_mul(b616, b629);
    unsigned b635 = stwo_m31_add(b633, b634);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b346 = base_params[184u];
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 306u, row_index, 0);
    unsigned b313 = base_params[173u];
    unsigned b314 = stwo_m31_mul(b150, b313);
    unsigned b315 = stwo_m31_sub(b40, b314);
    unsigned b347 = stwo_m31_mul(b346, b315);
    unsigned b348 = stwo_m31_add(b39, b347);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b412 = base_params[210u];
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 316u, row_index, 0);
    unsigned b391 = base_params[199u];
    unsigned b392 = stwo_m31_mul(b160, b391);
    unsigned b393 = stwo_m31_sub(b62, b392);
    unsigned b413 = stwo_m31_mul(b412, b393);
    unsigned b414 = stwo_m31_add(b61, b413);
    unsigned b617 = stwo_m31_add(b348, b414);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 327u, row_index, 0);
    unsigned b475 = base_params[238u];
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b476 = stwo_m31_mul(b475, b77);
    unsigned b477 = stwo_m31_add(b167, b476);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 337u, row_index, 0);
    unsigned b541 = base_params[264u];
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    unsigned b542 = stwo_m31_mul(b541, b99);
    unsigned b543 = stwo_m31_add(b177, b542);
    unsigned b628 = stwo_m31_add(b477, b543);
    unsigned b636 = stwo_m31_mul(b617, b628);
    unsigned b637 = stwo_m31_add(b635, b636);
    unsigned b349 = base_params[185u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 307u, row_index, 0);
    unsigned b316 = base_params[174u];
    unsigned b317 = stwo_m31_mul(b151, b316);
    unsigned b318 = stwo_m31_sub(b41, b317);
    unsigned b350 = stwo_m31_mul(b349, b318);
    unsigned b351 = stwo_m31_add(b150, b350);
    unsigned b415 = base_params[211u];
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 317u, row_index, 0);
    unsigned b394 = base_params[200u];
    unsigned b395 = stwo_m31_mul(b161, b394);
    unsigned b396 = stwo_m31_sub(b63, b395);
    unsigned b416 = stwo_m31_mul(b415, b396);
    unsigned b417 = stwo_m31_add(b160, b416);
    unsigned b618 = stwo_m31_add(b351, b417);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 326u, row_index, 0);
    unsigned b472 = base_params[237u];
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b439 = base_params[226u];
    unsigned b440 = stwo_m31_mul(b167, b439);
    unsigned b441 = stwo_m31_sub(b76, b440);
    unsigned b473 = stwo_m31_mul(b472, b441);
    unsigned b474 = stwo_m31_add(b166, b473);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 336u, row_index, 0);
    unsigned b538 = base_params[263u];
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b517 = base_params[252u];
    unsigned b518 = stwo_m31_mul(b177, b517);
    unsigned b519 = stwo_m31_sub(b98, b518);
    unsigned b539 = stwo_m31_mul(b538, b519);
    unsigned b540 = stwo_m31_add(b176, b539);
    unsigned b627 = stwo_m31_add(b474, b540);
    unsigned b638 = stwo_m31_mul(b618, b627);
    unsigned b639 = stwo_m31_add(b637, b638);
    unsigned b352 = base_params[186u];
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b353 = stwo_m31_mul(b352, b42);
    unsigned b354 = stwo_m31_add(b151, b353);
    unsigned b418 = base_params[212u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b419 = stwo_m31_mul(b418, b64);
    unsigned b420 = stwo_m31_add(b161, b419);
    unsigned b619 = stwo_m31_add(b354, b420);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b469 = base_params[236u];
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b436 = base_params[225u];
    unsigned b437 = stwo_m31_mul(b166, b436);
    unsigned b438 = stwo_m31_sub(b75, b437);
    unsigned b470 = stwo_m31_mul(b469, b438);
    unsigned b471 = stwo_m31_add(b74, b470);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    unsigned b535 = base_params[262u];
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b514 = base_params[251u];
    unsigned b515 = stwo_m31_mul(b176, b514);
    unsigned b516 = stwo_m31_sub(b97, b515);
    unsigned b536 = stwo_m31_mul(b535, b516);
    unsigned b537 = stwo_m31_add(b96, b536);
    unsigned b626 = stwo_m31_add(b471, b537);
    unsigned b640 = stwo_m31_mul(b619, b626);
    unsigned b641 = stwo_m31_add(b639, b640);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b355 = base_params[187u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 308u, row_index, 0);
    unsigned b319 = base_params[175u];
    unsigned b320 = stwo_m31_mul(b152, b319);
    unsigned b321 = stwo_m31_sub(b44, b320);
    unsigned b356 = stwo_m31_mul(b355, b321);
    unsigned b357 = stwo_m31_add(b43, b356);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b421 = base_params[213u];
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 318u, row_index, 0);
    unsigned b397 = base_params[201u];
    unsigned b398 = stwo_m31_mul(b162, b397);
    unsigned b399 = stwo_m31_sub(b66, b398);
    unsigned b422 = stwo_m31_mul(b421, b399);
    unsigned b423 = stwo_m31_add(b65, b422);
    unsigned b620 = stwo_m31_add(b357, b423);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 325u, row_index, 0);
    unsigned b466 = base_params[235u];
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b467 = stwo_m31_mul(b466, b73);
    unsigned b468 = stwo_m31_add(b165, b467);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 335u, row_index, 0);
    unsigned b532 = base_params[261u];
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    unsigned b533 = stwo_m31_mul(b532, b95);
    unsigned b534 = stwo_m31_add(b175, b533);
    unsigned b625 = stwo_m31_add(b468, b534);
    unsigned b642 = stwo_m31_mul(b620, b625);
    unsigned b643 = stwo_m31_add(b641, b642);
    unsigned b358 = base_params[188u];
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b359 = stwo_m31_mul(b358, b45);
    unsigned b360 = stwo_m31_add(b152, b359);
    unsigned b424 = base_params[214u];
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b425 = stwo_m31_mul(b424, b67);
    unsigned b426 = stwo_m31_add(b162, b425);
    unsigned b621 = stwo_m31_add(b360, b426);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 324u, row_index, 0);
    unsigned b463 = base_params[234u];
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b433 = base_params[224u];
    unsigned b434 = stwo_m31_mul(b165, b433);
    unsigned b435 = stwo_m31_sub(b72, b434);
    unsigned b464 = stwo_m31_mul(b463, b435);
    unsigned b465 = stwo_m31_add(b164, b464);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 334u, row_index, 0);
    unsigned b529 = base_params[260u];
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b511 = base_params[250u];
    unsigned b512 = stwo_m31_mul(b175, b511);
    unsigned b513 = stwo_m31_sub(b94, b512);
    unsigned b530 = stwo_m31_mul(b529, b513);
    unsigned b531 = stwo_m31_add(b174, b530);
    unsigned b624 = stwo_m31_add(b465, b531);
    unsigned b644 = stwo_m31_mul(b621, b624);
    unsigned b645 = stwo_m31_add(b643, b644);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b337 = base_params[181u];
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b307 = base_params[171u];
    unsigned b308 = stwo_m31_mul(b148, b307);
    unsigned b309 = stwo_m31_sub(b36, b308);
    unsigned b338 = stwo_m31_mul(b337, b309);
    unsigned b339 = stwo_m31_add(b35, b338);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b403 = base_params[207u];
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b385 = base_params[197u];
    unsigned b386 = stwo_m31_mul(b158, b385);
    unsigned b387 = stwo_m31_sub(b58, b386);
    unsigned b404 = stwo_m31_mul(b403, b387);
    unsigned b405 = stwo_m31_add(b57, b404);
    unsigned b614 = stwo_m31_add(b339, b405);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b361 = base_params[189u];
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b322 = base_params[176u];
    unsigned b323 = stwo_m31_mul(b153, b322);
    unsigned b324 = stwo_m31_sub(b47, b323);
    unsigned b362 = stwo_m31_mul(b361, b324);
    unsigned b363 = stwo_m31_add(b46, b362);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b427 = base_params[215u];
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 319u, row_index, 0);
    unsigned b400 = base_params[202u];
    unsigned b401 = stwo_m31_mul(b163, b400);
    unsigned b402 = stwo_m31_sub(b69, b401);
    unsigned b428 = stwo_m31_mul(b427, b402);
    unsigned b429 = stwo_m31_add(b68, b428);
    unsigned b622 = stwo_m31_add(b363, b429);
    unsigned b647 = stwo_m31_add(b614, b622);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b460 = base_params[233u];
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b430 = base_params[223u];
    unsigned b431 = stwo_m31_mul(b164, b430);
    unsigned b432 = stwo_m31_sub(b71, b431);
    unsigned b461 = stwo_m31_mul(b460, b432);
    unsigned b462 = stwo_m31_add(b70, b461);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    unsigned b526 = base_params[259u];
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b508 = base_params[249u];
    unsigned b509 = stwo_m31_mul(b174, b508);
    unsigned b510 = stwo_m31_sub(b93, b509);
    unsigned b527 = stwo_m31_mul(b526, b510);
    unsigned b528 = stwo_m31_add(b92, b527);
    unsigned b623 = stwo_m31_add(b462, b528);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b484 = base_params[241u];
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b445 = base_params[228u];
    unsigned b446 = stwo_m31_mul(b169, b445);
    unsigned b447 = stwo_m31_sub(b82, b446);
    unsigned b485 = stwo_m31_mul(b484, b447);
    unsigned b486 = stwo_m31_add(b81, b485);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    unsigned b550 = base_params[267u];
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 339u, row_index, 0);
    unsigned b523 = base_params[254u];
    unsigned b524 = stwo_m31_mul(b179, b523);
    unsigned b525 = stwo_m31_sub(b104, b524);
    unsigned b551 = stwo_m31_mul(b550, b525);
    unsigned b552 = stwo_m31_add(b103, b551);
    unsigned b631 = stwo_m31_add(b486, b552);
    unsigned b648 = stwo_m31_add(b623, b631);
    unsigned b649 = stwo_m31_mul(b647, b648);
    unsigned b632 = stwo_m31_mul(b614, b623);
    unsigned b650 = stwo_m31_sub(b649, b632);
    unsigned b646 = stwo_m31_mul(b622, b631);
    unsigned b651 = stwo_m31_sub(b650, b646);
    unsigned b652 = stwo_m31_add(b645, b651);
    unsigned b560 = stwo_m31_mul(b342, b483);
    unsigned b561 = stwo_m31_mul(b345, b480);
    unsigned b562 = stwo_m31_add(b560, b561);
    unsigned b563 = stwo_m31_mul(b348, b477);
    unsigned b564 = stwo_m31_add(b562, b563);
    unsigned b565 = stwo_m31_mul(b351, b474);
    unsigned b566 = stwo_m31_add(b564, b565);
    unsigned b567 = stwo_m31_mul(b354, b471);
    unsigned b568 = stwo_m31_add(b566, b567);
    unsigned b569 = stwo_m31_mul(b357, b468);
    unsigned b570 = stwo_m31_add(b568, b569);
    unsigned b571 = stwo_m31_mul(b360, b465);
    unsigned b572 = stwo_m31_add(b570, b571);
    unsigned b587 = stwo_m31_add(b339, b363);
    unsigned b588 = stwo_m31_add(b462, b486);
    unsigned b589 = stwo_m31_mul(b587, b588);
    unsigned b559 = stwo_m31_mul(b339, b462);
    unsigned b590 = stwo_m31_sub(b589, b559);
    unsigned b573 = stwo_m31_mul(b363, b486);
    unsigned b591 = stwo_m31_sub(b590, b573);
    unsigned b592 = stwo_m31_add(b572, b591);
    unsigned b653 = stwo_m31_sub(b652, b592);
    unsigned b594 = stwo_m31_mul(b408, b549);
    unsigned b595 = stwo_m31_mul(b411, b546);
    unsigned b596 = stwo_m31_add(b594, b595);
    unsigned b597 = stwo_m31_mul(b414, b543);
    unsigned b598 = stwo_m31_add(b596, b597);
    unsigned b599 = stwo_m31_mul(b417, b540);
    unsigned b600 = stwo_m31_add(b598, b599);
    unsigned b601 = stwo_m31_mul(b420, b537);
    unsigned b602 = stwo_m31_add(b600, b601);
    unsigned b603 = stwo_m31_mul(b423, b534);
    unsigned b604 = stwo_m31_add(b602, b603);
    unsigned b605 = stwo_m31_mul(b426, b531);
    unsigned b606 = stwo_m31_add(b604, b605);
    unsigned b608 = stwo_m31_add(b405, b429);
    unsigned b609 = stwo_m31_add(b528, b552);
    unsigned b610 = stwo_m31_mul(b608, b609);
    unsigned b593 = stwo_m31_mul(b405, b528);
    unsigned b611 = stwo_m31_sub(b610, b593);
    unsigned b607 = stwo_m31_mul(b429, b552);
    unsigned b612 = stwo_m31_sub(b611, b607);
    unsigned b613 = stwo_m31_add(b606, b612);
    unsigned b654 = stwo_m31_sub(b653, b613);
    unsigned b655 = stwo_m31_add(b586, b654);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 293u, row_index, 0);
    unsigned b259 = base_params[144u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b260 = stwo_m31_mul(b259, b21);
    unsigned b261 = stwo_m31_add(b141, b260);
    unsigned b671 = stwo_m31_mul(b116, b261);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b256 = base_params[143u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b211 = base_params[128u];
    unsigned b212 = stwo_m31_mul(b141, b211);
    unsigned b213 = stwo_m31_sub(b20, b212);
    unsigned b257 = stwo_m31_mul(b256, b213);
    unsigned b258 = stwo_m31_add(b19, b257);
    unsigned b672 = stwo_m31_mul(b117, b258);
    unsigned b673 = stwo_m31_add(b671, b672);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 292u, row_index, 0);
    unsigned b253 = base_params[142u];
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b254 = stwo_m31_mul(b253, b18);
    unsigned b255 = stwo_m31_add(b140, b254);
    unsigned b674 = stwo_m31_mul(b118, b255);
    unsigned b675 = stwo_m31_add(b673, b674);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 291u, row_index, 0);
    unsigned b250 = base_params[141u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b208 = base_params[127u];
    unsigned b209 = stwo_m31_mul(b140, b208);
    unsigned b210 = stwo_m31_sub(b17, b209);
    unsigned b251 = stwo_m31_mul(b250, b210);
    unsigned b252 = stwo_m31_add(b139, b251);
    unsigned b676 = stwo_m31_mul(b119, b252);
    unsigned b677 = stwo_m31_add(b675, b676);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b247 = base_params[140u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b205 = base_params[126u];
    unsigned b206 = stwo_m31_mul(b139, b205);
    unsigned b207 = stwo_m31_sub(b16, b206);
    unsigned b248 = stwo_m31_mul(b247, b207);
    unsigned b249 = stwo_m31_add(b15, b248);
    unsigned b678 = stwo_m31_mul(b120, b249);
    unsigned b679 = stwo_m31_add(b677, b678);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 290u, row_index, 0);
    unsigned b244 = base_params[139u];
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b245 = stwo_m31_mul(b244, b14);
    unsigned b246 = stwo_m31_add(b138, b245);
    unsigned b680 = stwo_m31_mul(b121, b246);
    unsigned b681 = stwo_m31_add(b679, b680);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 267u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 289u, row_index, 0);
    unsigned b241 = base_params[138u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b202 = base_params[125u];
    unsigned b203 = stwo_m31_mul(b138, b202);
    unsigned b204 = stwo_m31_sub(b13, b203);
    unsigned b242 = stwo_m31_mul(b241, b204);
    unsigned b243 = stwo_m31_add(b137, b242);
    unsigned b682 = stwo_m31_mul(b122, b243);
    unsigned b683 = stwo_m31_add(b681, b682);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 269u, row_index, 0);
    unsigned b712 = stwo_m31_add(b108, b124);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 288u, row_index, 0);
    unsigned b235 = base_params[136u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b236 = stwo_m31_mul(b235, b10);
    unsigned b237 = stwo_m31_add(b136, b236);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 298u, row_index, 0);
    unsigned b301 = base_params[162u];
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b302 = stwo_m31_mul(b301, b32);
    unsigned b303 = stwo_m31_add(b146, b302);
    unsigned b727 = stwo_m31_add(b237, b303);
    unsigned b730 = stwo_m31_mul(b712, b727);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 270u, row_index, 0);
    unsigned b713 = stwo_m31_add(b109, b125);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b232 = base_params[135u];
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b196 = base_params[123u];
    unsigned b197 = stwo_m31_mul(b136, b196);
    unsigned b198 = stwo_m31_sub(b9, b197);
    unsigned b233 = stwo_m31_mul(b232, b198);
    unsigned b234 = stwo_m31_add(b8, b233);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b298 = base_params[161u];
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b274 = base_params[149u];
    unsigned b275 = stwo_m31_mul(b146, b274);
    unsigned b276 = stwo_m31_sub(b31, b275);
    unsigned b299 = stwo_m31_mul(b298, b276);
    unsigned b300 = stwo_m31_add(b30, b299);
    unsigned b726 = stwo_m31_add(b234, b300);
    unsigned b731 = stwo_m31_mul(b713, b726);
    unsigned b732 = stwo_m31_add(b730, b731);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 271u, row_index, 0);
    unsigned b714 = stwo_m31_add(b110, b126);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 287u, row_index, 0);
    unsigned b229 = base_params[134u];
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b230 = stwo_m31_mul(b229, b7);
    unsigned b231 = stwo_m31_add(b135, b230);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 297u, row_index, 0);
    unsigned b295 = base_params[160u];
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b296 = stwo_m31_mul(b295, b29);
    unsigned b297 = stwo_m31_add(b145, b296);
    unsigned b725 = stwo_m31_add(b231, b297);
    unsigned b733 = stwo_m31_mul(b714, b725);
    unsigned b734 = stwo_m31_add(b732, b733);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 272u, row_index, 0);
    unsigned b715 = stwo_m31_add(b111, b127);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 286u, row_index, 0);
    unsigned b226 = base_params[133u];
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b193 = base_params[122u];
    unsigned b194 = stwo_m31_mul(b135, b193);
    unsigned b195 = stwo_m31_sub(b6, b194);
    unsigned b227 = stwo_m31_mul(b226, b195);
    unsigned b228 = stwo_m31_add(b134, b227);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 296u, row_index, 0);
    unsigned b292 = base_params[159u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b271 = base_params[148u];
    unsigned b272 = stwo_m31_mul(b145, b271);
    unsigned b273 = stwo_m31_sub(b28, b272);
    unsigned b293 = stwo_m31_mul(b292, b273);
    unsigned b294 = stwo_m31_add(b144, b293);
    unsigned b724 = stwo_m31_add(b228, b294);
    unsigned b735 = stwo_m31_mul(b715, b724);
    unsigned b736 = stwo_m31_add(b734, b735);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 257u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 273u, row_index, 0);
    unsigned b716 = stwo_m31_add(b112, b128);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b223 = base_params[132u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b190 = base_params[121u];
    unsigned b191 = stwo_m31_mul(b134, b190);
    unsigned b192 = stwo_m31_sub(b5, b191);
    unsigned b224 = stwo_m31_mul(b223, b192);
    unsigned b225 = stwo_m31_add(b4, b224);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b289 = base_params[158u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b268 = base_params[147u];
    unsigned b269 = stwo_m31_mul(b144, b268);
    unsigned b270 = stwo_m31_sub(b27, b269);
    unsigned b290 = stwo_m31_mul(b289, b270);
    unsigned b291 = stwo_m31_add(b26, b290);
    unsigned b723 = stwo_m31_add(b225, b291);
    unsigned b737 = stwo_m31_mul(b716, b723);
    unsigned b738 = stwo_m31_add(b736, b737);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 274u, row_index, 0);
    unsigned b717 = stwo_m31_add(b113, b129);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 285u, row_index, 0);
    unsigned b220 = base_params[131u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b221 = stwo_m31_mul(b220, b3);
    unsigned b222 = stwo_m31_add(b133, b221);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 295u, row_index, 0);
    unsigned b286 = base_params[157u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b287 = stwo_m31_mul(b286, b25);
    unsigned b288 = stwo_m31_add(b143, b287);
    unsigned b722 = stwo_m31_add(b222, b288);
    unsigned b739 = stwo_m31_mul(b717, b722);
    unsigned b740 = stwo_m31_add(b738, b739);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 275u, row_index, 0);
    unsigned b718 = stwo_m31_add(b114, b130);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 284u, row_index, 0);
    unsigned b217 = base_params[130u];
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b187 = base_params[120u];
    unsigned b188 = stwo_m31_mul(b133, b187);
    unsigned b189 = stwo_m31_sub(b2, b188);
    unsigned b218 = stwo_m31_mul(b217, b189);
    unsigned b219 = stwo_m31_add(b132, b218);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 294u, row_index, 0);
    unsigned b283 = base_params[156u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b265 = base_params[146u];
    unsigned b266 = stwo_m31_mul(b143, b265);
    unsigned b267 = stwo_m31_sub(b24, b266);
    unsigned b284 = stwo_m31_mul(b283, b267);
    unsigned b285 = stwo_m31_add(b142, b284);
    unsigned b721 = stwo_m31_add(b219, b285);
    unsigned b741 = stwo_m31_mul(b718, b721);
    unsigned b742 = stwo_m31_add(b740, b741);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 268u, row_index, 0);
    unsigned b711 = stwo_m31_add(b107, b123);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 276u, row_index, 0);
    unsigned b719 = stwo_m31_add(b115, b131);
    unsigned b744 = stwo_m31_add(b711, b719);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b214 = base_params[129u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b184 = base_params[119u];
    unsigned b185 = stwo_m31_mul(b132, b184);
    unsigned b186 = stwo_m31_sub(b1, b185);
    unsigned b215 = stwo_m31_mul(b214, b186);
    unsigned b216 = stwo_m31_add(b0, b215);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b280 = base_params[155u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b262 = base_params[145u];
    unsigned b263 = stwo_m31_mul(b142, b262);
    unsigned b264 = stwo_m31_sub(b23, b263);
    unsigned b281 = stwo_m31_mul(b280, b264);
    unsigned b282 = stwo_m31_add(b22, b281);
    unsigned b720 = stwo_m31_add(b216, b282);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b238 = base_params[137u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b199 = base_params[124u];
    unsigned b200 = stwo_m31_mul(b137, b199);
    unsigned b201 = stwo_m31_sub(b12, b200);
    unsigned b239 = stwo_m31_mul(b238, b201);
    unsigned b240 = stwo_m31_add(b11, b239);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b304 = base_params[163u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 299u, row_index, 0);
    unsigned b277 = base_params[150u];
    unsigned b278 = stwo_m31_mul(b147, b277);
    unsigned b279 = stwo_m31_sub(b34, b278);
    unsigned b305 = stwo_m31_mul(b304, b279);
    unsigned b306 = stwo_m31_add(b33, b305);
    unsigned b728 = stwo_m31_add(b240, b306);
    unsigned b745 = stwo_m31_add(b720, b728);
    unsigned b746 = stwo_m31_mul(b744, b745);
    unsigned b729 = stwo_m31_mul(b711, b720);
    unsigned b747 = stwo_m31_sub(b746, b729);
    unsigned b743 = stwo_m31_mul(b719, b728);
    unsigned b748 = stwo_m31_sub(b747, b743);
    unsigned b749 = stwo_m31_add(b742, b748);
    unsigned b657 = stwo_m31_mul(b108, b237);
    unsigned b658 = stwo_m31_mul(b109, b234);
    unsigned b659 = stwo_m31_add(b657, b658);
    unsigned b660 = stwo_m31_mul(b110, b231);
    unsigned b661 = stwo_m31_add(b659, b660);
    unsigned b662 = stwo_m31_mul(b111, b228);
    unsigned b663 = stwo_m31_add(b661, b662);
    unsigned b664 = stwo_m31_mul(b112, b225);
    unsigned b665 = stwo_m31_add(b663, b664);
    unsigned b666 = stwo_m31_mul(b113, b222);
    unsigned b667 = stwo_m31_add(b665, b666);
    unsigned b668 = stwo_m31_mul(b114, b219);
    unsigned b669 = stwo_m31_add(b667, b668);
    unsigned b684 = stwo_m31_add(b107, b115);
    unsigned b685 = stwo_m31_add(b216, b240);
    unsigned b686 = stwo_m31_mul(b684, b685);
    unsigned b656 = stwo_m31_mul(b107, b216);
    unsigned b687 = stwo_m31_sub(b686, b656);
    unsigned b670 = stwo_m31_mul(b115, b240);
    unsigned b688 = stwo_m31_sub(b687, b670);
    unsigned b689 = stwo_m31_add(b669, b688);
    unsigned b750 = stwo_m31_sub(b749, b689);
    unsigned b691 = stwo_m31_mul(b124, b303);
    unsigned b692 = stwo_m31_mul(b125, b300);
    unsigned b693 = stwo_m31_add(b691, b692);
    unsigned b694 = stwo_m31_mul(b126, b297);
    unsigned b695 = stwo_m31_add(b693, b694);
    unsigned b696 = stwo_m31_mul(b127, b294);
    unsigned b697 = stwo_m31_add(b695, b696);
    unsigned b698 = stwo_m31_mul(b128, b291);
    unsigned b699 = stwo_m31_add(b697, b698);
    unsigned b700 = stwo_m31_mul(b129, b288);
    unsigned b701 = stwo_m31_add(b699, b700);
    unsigned b702 = stwo_m31_mul(b130, b285);
    unsigned b703 = stwo_m31_add(b701, b702);
    unsigned b705 = stwo_m31_add(b123, b131);
    unsigned b706 = stwo_m31_add(b282, b306);
    unsigned b707 = stwo_m31_mul(b705, b706);
    unsigned b690 = stwo_m31_mul(b123, b282);
    unsigned b708 = stwo_m31_sub(b707, b690);
    unsigned b704 = stwo_m31_mul(b131, b306);
    unsigned b709 = stwo_m31_sub(b708, b704);
    unsigned b710 = stwo_m31_add(b703, b709);
    unsigned b751 = stwo_m31_sub(b750, b710);
    unsigned b752 = stwo_m31_add(b683, b751);
    unsigned b754 = stwo_m31_sub(b655, b752);
    unsigned b755 = stwo_m31_add(b753, b754);
    unsigned b756 = base_params[376u];
    unsigned b757 = stwo_m31_mul(b755, b756);
    unsigned b758 = stwo_m31_sub(b182, b757);
    unsigned b183 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b758, b183, b183, b183 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
