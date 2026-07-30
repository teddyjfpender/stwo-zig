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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_0af04daf5797dfbf(
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
    unsigned b189 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 389u, row_index, 0);
    unsigned b188 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 388u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 359u, row_index, 0);
    unsigned b581 = base_params[320u];
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    unsigned b187 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 360u, row_index, 0);
    unsigned b578 = base_params[307u];
    unsigned b579 = stwo_m31_mul(b187, b578);
    unsigned b580 = stwo_m31_sub(b108, b579);
    unsigned b582 = stwo_m31_mul(b581, b580);
    unsigned b583 = stwo_m31_add(b186, b582);
    unsigned b814 = stwo_m31_sub(b188, b583);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 310u, row_index, 0);
    unsigned b380 = base_params[191u];
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b381 = stwo_m31_mul(b380, b50);
    unsigned b382 = stwo_m31_add(b158, b381);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 333u, row_index, 0);
    unsigned b524 = base_params[248u];
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b525 = stwo_m31_mul(b524, b93);
    unsigned b526 = stwo_m31_add(b178, b525);
    unsigned b601 = stwo_m31_mul(b382, b526);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b383 = base_params[192u];
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 311u, row_index, 0);
    unsigned b341 = base_params[178u];
    unsigned b342 = stwo_m31_mul(b159, b341);
    unsigned b343 = stwo_m31_sub(b52, b342);
    unsigned b384 = stwo_m31_mul(b383, b343);
    unsigned b385 = stwo_m31_add(b51, b384);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b521 = base_params[247u];
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b476 = base_params[232u];
    unsigned b477 = stwo_m31_mul(b178, b476);
    unsigned b478 = stwo_m31_sub(b92, b477);
    unsigned b522 = stwo_m31_mul(b521, b478);
    unsigned b523 = stwo_m31_add(b91, b522);
    unsigned b602 = stwo_m31_mul(b385, b523);
    unsigned b603 = stwo_m31_add(b601, b602);
    unsigned b386 = base_params[193u];
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 312u, row_index, 0);
    unsigned b344 = base_params[179u];
    unsigned b345 = stwo_m31_mul(b160, b344);
    unsigned b346 = stwo_m31_sub(b53, b345);
    unsigned b387 = stwo_m31_mul(b386, b346);
    unsigned b388 = stwo_m31_add(b159, b387);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 332u, row_index, 0);
    unsigned b518 = base_params[246u];
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b519 = stwo_m31_mul(b518, b90);
    unsigned b520 = stwo_m31_add(b177, b519);
    unsigned b604 = stwo_m31_mul(b388, b520);
    unsigned b605 = stwo_m31_add(b603, b604);
    unsigned b389 = base_params[194u];
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b390 = stwo_m31_mul(b389, b54);
    unsigned b391 = stwo_m31_add(b160, b390);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 331u, row_index, 0);
    unsigned b515 = base_params[245u];
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b473 = base_params[231u];
    unsigned b474 = stwo_m31_mul(b177, b473);
    unsigned b475 = stwo_m31_sub(b89, b474);
    unsigned b516 = stwo_m31_mul(b515, b475);
    unsigned b517 = stwo_m31_add(b176, b516);
    unsigned b606 = stwo_m31_mul(b391, b517);
    unsigned b607 = stwo_m31_add(b605, b606);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b392 = base_params[195u];
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 313u, row_index, 0);
    unsigned b347 = base_params[180u];
    unsigned b348 = stwo_m31_mul(b161, b347);
    unsigned b349 = stwo_m31_sub(b56, b348);
    unsigned b393 = stwo_m31_mul(b392, b349);
    unsigned b394 = stwo_m31_add(b55, b393);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b512 = base_params[244u];
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b470 = base_params[230u];
    unsigned b471 = stwo_m31_mul(b176, b470);
    unsigned b472 = stwo_m31_sub(b88, b471);
    unsigned b513 = stwo_m31_mul(b512, b472);
    unsigned b514 = stwo_m31_add(b87, b513);
    unsigned b608 = stwo_m31_mul(b394, b514);
    unsigned b609 = stwo_m31_add(b607, b608);
    unsigned b395 = base_params[196u];
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b396 = stwo_m31_mul(b395, b57);
    unsigned b397 = stwo_m31_add(b161, b396);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 330u, row_index, 0);
    unsigned b509 = base_params[243u];
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b510 = stwo_m31_mul(b509, b86);
    unsigned b511 = stwo_m31_add(b175, b510);
    unsigned b610 = stwo_m31_mul(b397, b511);
    unsigned b611 = stwo_m31_add(b609, b610);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 305u, row_index, 0);
    unsigned b356 = base_params[183u];
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b357 = stwo_m31_mul(b356, b39);
    unsigned b358 = stwo_m31_add(b153, b357);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 315u, row_index, 0);
    unsigned b425 = base_params[209u];
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b426 = stwo_m31_mul(b425, b61);
    unsigned b427 = stwo_m31_add(b163, b426);
    unsigned b651 = stwo_m31_add(b358, b427);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 328u, row_index, 0);
    unsigned b500 = base_params[240u];
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b501 = stwo_m31_mul(b500, b82);
    unsigned b502 = stwo_m31_add(b173, b501);
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 338u, row_index, 0);
    unsigned b569 = base_params[266u];
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    unsigned b570 = stwo_m31_mul(b569, b104);
    unsigned b571 = stwo_m31_add(b183, b570);
    unsigned b666 = stwo_m31_add(b502, b571);
    unsigned b672 = stwo_m31_mul(b651, b666);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b359 = base_params[184u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 306u, row_index, 0);
    unsigned b326 = base_params[173u];
    unsigned b327 = stwo_m31_mul(b154, b326);
    unsigned b328 = stwo_m31_sub(b41, b327);
    unsigned b360 = stwo_m31_mul(b359, b328);
    unsigned b361 = stwo_m31_add(b40, b360);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b428 = base_params[210u];
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 316u, row_index, 0);
    unsigned b404 = base_params[199u];
    unsigned b405 = stwo_m31_mul(b164, b404);
    unsigned b406 = stwo_m31_sub(b63, b405);
    unsigned b429 = stwo_m31_mul(b428, b406);
    unsigned b430 = stwo_m31_add(b62, b429);
    unsigned b652 = stwo_m31_add(b361, b430);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b497 = base_params[239u];
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b461 = base_params[227u];
    unsigned b462 = stwo_m31_mul(b173, b461);
    unsigned b463 = stwo_m31_sub(b81, b462);
    unsigned b498 = stwo_m31_mul(b497, b463);
    unsigned b499 = stwo_m31_add(b80, b498);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    unsigned b566 = base_params[265u];
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b539 = base_params[253u];
    unsigned b540 = stwo_m31_mul(b183, b539);
    unsigned b541 = stwo_m31_sub(b103, b540);
    unsigned b567 = stwo_m31_mul(b566, b541);
    unsigned b568 = stwo_m31_add(b102, b567);
    unsigned b665 = stwo_m31_add(b499, b568);
    unsigned b673 = stwo_m31_mul(b652, b665);
    unsigned b674 = stwo_m31_add(b672, b673);
    unsigned b362 = base_params[185u];
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 307u, row_index, 0);
    unsigned b329 = base_params[174u];
    unsigned b330 = stwo_m31_mul(b155, b329);
    unsigned b331 = stwo_m31_sub(b42, b330);
    unsigned b363 = stwo_m31_mul(b362, b331);
    unsigned b364 = stwo_m31_add(b154, b363);
    unsigned b431 = base_params[211u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 317u, row_index, 0);
    unsigned b407 = base_params[200u];
    unsigned b408 = stwo_m31_mul(b165, b407);
    unsigned b409 = stwo_m31_sub(b64, b408);
    unsigned b432 = stwo_m31_mul(b431, b409);
    unsigned b433 = stwo_m31_add(b164, b432);
    unsigned b653 = stwo_m31_add(b364, b433);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 327u, row_index, 0);
    unsigned b494 = base_params[238u];
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b495 = stwo_m31_mul(b494, b79);
    unsigned b496 = stwo_m31_add(b172, b495);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 337u, row_index, 0);
    unsigned b563 = base_params[264u];
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    unsigned b564 = stwo_m31_mul(b563, b101);
    unsigned b565 = stwo_m31_add(b182, b564);
    unsigned b664 = stwo_m31_add(b496, b565);
    unsigned b675 = stwo_m31_mul(b653, b664);
    unsigned b676 = stwo_m31_add(b674, b675);
    unsigned b365 = base_params[186u];
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b366 = stwo_m31_mul(b365, b43);
    unsigned b367 = stwo_m31_add(b155, b366);
    unsigned b434 = base_params[212u];
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b435 = stwo_m31_mul(b434, b65);
    unsigned b436 = stwo_m31_add(b165, b435);
    unsigned b654 = stwo_m31_add(b367, b436);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 326u, row_index, 0);
    unsigned b491 = base_params[237u];
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b458 = base_params[226u];
    unsigned b459 = stwo_m31_mul(b172, b458);
    unsigned b460 = stwo_m31_sub(b78, b459);
    unsigned b492 = stwo_m31_mul(b491, b460);
    unsigned b493 = stwo_m31_add(b171, b492);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 336u, row_index, 0);
    unsigned b560 = base_params[263u];
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b536 = base_params[252u];
    unsigned b537 = stwo_m31_mul(b182, b536);
    unsigned b538 = stwo_m31_sub(b100, b537);
    unsigned b561 = stwo_m31_mul(b560, b538);
    unsigned b562 = stwo_m31_add(b181, b561);
    unsigned b663 = stwo_m31_add(b493, b562);
    unsigned b677 = stwo_m31_mul(b654, b663);
    unsigned b678 = stwo_m31_add(b676, b677);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b368 = base_params[187u];
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 308u, row_index, 0);
    unsigned b332 = base_params[175u];
    unsigned b333 = stwo_m31_mul(b156, b332);
    unsigned b334 = stwo_m31_sub(b45, b333);
    unsigned b369 = stwo_m31_mul(b368, b334);
    unsigned b370 = stwo_m31_add(b44, b369);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b437 = base_params[213u];
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 318u, row_index, 0);
    unsigned b410 = base_params[201u];
    unsigned b411 = stwo_m31_mul(b166, b410);
    unsigned b412 = stwo_m31_sub(b67, b411);
    unsigned b438 = stwo_m31_mul(b437, b412);
    unsigned b439 = stwo_m31_add(b66, b438);
    unsigned b655 = stwo_m31_add(b370, b439);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b488 = base_params[236u];
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b455 = base_params[225u];
    unsigned b456 = stwo_m31_mul(b171, b455);
    unsigned b457 = stwo_m31_sub(b77, b456);
    unsigned b489 = stwo_m31_mul(b488, b457);
    unsigned b490 = stwo_m31_add(b76, b489);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    unsigned b557 = base_params[262u];
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b533 = base_params[251u];
    unsigned b534 = stwo_m31_mul(b181, b533);
    unsigned b535 = stwo_m31_sub(b99, b534);
    unsigned b558 = stwo_m31_mul(b557, b535);
    unsigned b559 = stwo_m31_add(b98, b558);
    unsigned b662 = stwo_m31_add(b490, b559);
    unsigned b679 = stwo_m31_mul(b655, b662);
    unsigned b680 = stwo_m31_add(b678, b679);
    unsigned b371 = base_params[188u];
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b372 = stwo_m31_mul(b371, b46);
    unsigned b373 = stwo_m31_add(b156, b372);
    unsigned b440 = base_params[214u];
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b441 = stwo_m31_mul(b440, b68);
    unsigned b442 = stwo_m31_add(b166, b441);
    unsigned b656 = stwo_m31_add(b373, b442);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 325u, row_index, 0);
    unsigned b485 = base_params[235u];
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b486 = stwo_m31_mul(b485, b75);
    unsigned b487 = stwo_m31_add(b170, b486);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 335u, row_index, 0);
    unsigned b554 = base_params[261u];
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    unsigned b555 = stwo_m31_mul(b554, b97);
    unsigned b556 = stwo_m31_add(b180, b555);
    unsigned b661 = stwo_m31_add(b487, b556);
    unsigned b681 = stwo_m31_mul(b656, b661);
    unsigned b682 = stwo_m31_add(b680, b681);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b350 = base_params[181u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 304u, row_index, 0);
    unsigned b320 = base_params[171u];
    unsigned b321 = stwo_m31_mul(b152, b320);
    unsigned b322 = stwo_m31_sub(b37, b321);
    unsigned b351 = stwo_m31_mul(b350, b322);
    unsigned b352 = stwo_m31_add(b36, b351);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b419 = base_params[207u];
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 314u, row_index, 0);
    unsigned b398 = base_params[197u];
    unsigned b399 = stwo_m31_mul(b162, b398);
    unsigned b400 = stwo_m31_sub(b59, b399);
    unsigned b420 = stwo_m31_mul(b419, b400);
    unsigned b421 = stwo_m31_add(b58, b420);
    unsigned b649 = stwo_m31_add(b352, b421);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b374 = base_params[189u];
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 309u, row_index, 0);
    unsigned b335 = base_params[176u];
    unsigned b336 = stwo_m31_mul(b157, b335);
    unsigned b337 = stwo_m31_sub(b48, b336);
    unsigned b375 = stwo_m31_mul(b374, b337);
    unsigned b376 = stwo_m31_add(b47, b375);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b443 = base_params[215u];
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 319u, row_index, 0);
    unsigned b413 = base_params[202u];
    unsigned b414 = stwo_m31_mul(b167, b413);
    unsigned b415 = stwo_m31_sub(b70, b414);
    unsigned b444 = stwo_m31_mul(b443, b415);
    unsigned b445 = stwo_m31_add(b69, b444);
    unsigned b657 = stwo_m31_add(b376, b445);
    unsigned b686 = stwo_m31_add(b649, b657);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 324u, row_index, 0);
    unsigned b482 = base_params[234u];
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b452 = base_params[224u];
    unsigned b453 = stwo_m31_mul(b170, b452);
    unsigned b454 = stwo_m31_sub(b74, b453);
    unsigned b483 = stwo_m31_mul(b482, b454);
    unsigned b484 = stwo_m31_add(b169, b483);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 334u, row_index, 0);
    unsigned b551 = base_params[260u];
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b530 = base_params[250u];
    unsigned b531 = stwo_m31_mul(b180, b530);
    unsigned b532 = stwo_m31_sub(b96, b531);
    unsigned b552 = stwo_m31_mul(b551, b532);
    unsigned b553 = stwo_m31_add(b179, b552);
    unsigned b660 = stwo_m31_add(b484, b553);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 329u, row_index, 0);
    unsigned b506 = base_params[242u];
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b467 = base_params[229u];
    unsigned b468 = stwo_m31_mul(b175, b467);
    unsigned b469 = stwo_m31_sub(b85, b468);
    unsigned b507 = stwo_m31_mul(b506, b469);
    unsigned b508 = stwo_m31_add(b174, b507);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 339u, row_index, 0);
    unsigned b575 = base_params[268u];
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 340u, row_index, 0);
    unsigned b545 = base_params[255u];
    unsigned b546 = stwo_m31_mul(b185, b545);
    unsigned b547 = stwo_m31_sub(b107, b546);
    unsigned b576 = stwo_m31_mul(b575, b547);
    unsigned b577 = stwo_m31_add(b184, b576);
    unsigned b668 = stwo_m31_add(b508, b577);
    unsigned b689 = stwo_m31_add(b660, b668);
    unsigned b690 = stwo_m31_mul(b686, b689);
    unsigned b353 = base_params[182u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b323 = base_params[172u];
    unsigned b324 = stwo_m31_mul(b153, b323);
    unsigned b325 = stwo_m31_sub(b38, b324);
    unsigned b354 = stwo_m31_mul(b353, b325);
    unsigned b355 = stwo_m31_add(b152, b354);
    unsigned b422 = base_params[208u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b401 = base_params[198u];
    unsigned b402 = stwo_m31_mul(b163, b401);
    unsigned b403 = stwo_m31_sub(b60, b402);
    unsigned b423 = stwo_m31_mul(b422, b403);
    unsigned b424 = stwo_m31_add(b162, b423);
    unsigned b650 = stwo_m31_add(b355, b424);
    unsigned b377 = base_params[190u];
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b338 = base_params[177u];
    unsigned b339 = stwo_m31_mul(b158, b338);
    unsigned b340 = stwo_m31_sub(b49, b339);
    unsigned b378 = stwo_m31_mul(b377, b340);
    unsigned b379 = stwo_m31_add(b157, b378);
    unsigned b446 = base_params[216u];
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 320u, row_index, 0);
    unsigned b416 = base_params[203u];
    unsigned b417 = stwo_m31_mul(b168, b416);
    unsigned b418 = stwo_m31_sub(b71, b417);
    unsigned b447 = stwo_m31_mul(b446, b418);
    unsigned b448 = stwo_m31_add(b167, b447);
    unsigned b658 = stwo_m31_add(b379, b448);
    unsigned b687 = stwo_m31_add(b650, b658);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b479 = base_params[233u];
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b449 = base_params[223u];
    unsigned b450 = stwo_m31_mul(b169, b449);
    unsigned b451 = stwo_m31_sub(b73, b450);
    unsigned b480 = stwo_m31_mul(b479, b451);
    unsigned b481 = stwo_m31_add(b72, b480);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    unsigned b548 = base_params[259u];
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b527 = base_params[249u];
    unsigned b528 = stwo_m31_mul(b179, b527);
    unsigned b529 = stwo_m31_sub(b95, b528);
    unsigned b549 = stwo_m31_mul(b548, b529);
    unsigned b550 = stwo_m31_add(b94, b549);
    unsigned b659 = stwo_m31_add(b481, b550);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b503 = base_params[241u];
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b464 = base_params[228u];
    unsigned b465 = stwo_m31_mul(b174, b464);
    unsigned b466 = stwo_m31_sub(b84, b465);
    unsigned b504 = stwo_m31_mul(b503, b466);
    unsigned b505 = stwo_m31_add(b83, b504);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    unsigned b572 = base_params[267u];
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b542 = base_params[254u];
    unsigned b543 = stwo_m31_mul(b184, b542);
    unsigned b544 = stwo_m31_sub(b106, b543);
    unsigned b573 = stwo_m31_mul(b572, b544);
    unsigned b574 = stwo_m31_add(b105, b573);
    unsigned b667 = stwo_m31_add(b505, b574);
    unsigned b688 = stwo_m31_add(b659, b667);
    unsigned b691 = stwo_m31_mul(b687, b688);
    unsigned b692 = stwo_m31_add(b690, b691);
    unsigned b669 = stwo_m31_mul(b649, b660);
    unsigned b670 = stwo_m31_mul(b650, b659);
    unsigned b671 = stwo_m31_add(b669, b670);
    unsigned b693 = stwo_m31_sub(b692, b671);
    unsigned b683 = stwo_m31_mul(b657, b668);
    unsigned b684 = stwo_m31_mul(b658, b667);
    unsigned b685 = stwo_m31_add(b683, b684);
    unsigned b694 = stwo_m31_sub(b693, b685);
    unsigned b695 = stwo_m31_add(b682, b694);
    unsigned b587 = stwo_m31_mul(b358, b502);
    unsigned b588 = stwo_m31_mul(b361, b499);
    unsigned b589 = stwo_m31_add(b587, b588);
    unsigned b590 = stwo_m31_mul(b364, b496);
    unsigned b591 = stwo_m31_add(b589, b590);
    unsigned b592 = stwo_m31_mul(b367, b493);
    unsigned b593 = stwo_m31_add(b591, b592);
    unsigned b594 = stwo_m31_mul(b370, b490);
    unsigned b595 = stwo_m31_add(b593, b594);
    unsigned b596 = stwo_m31_mul(b373, b487);
    unsigned b597 = stwo_m31_add(b595, b596);
    unsigned b612 = stwo_m31_add(b352, b376);
    unsigned b615 = stwo_m31_add(b484, b508);
    unsigned b616 = stwo_m31_mul(b612, b615);
    unsigned b613 = stwo_m31_add(b355, b379);
    unsigned b614 = stwo_m31_add(b481, b505);
    unsigned b617 = stwo_m31_mul(b613, b614);
    unsigned b618 = stwo_m31_add(b616, b617);
    unsigned b584 = stwo_m31_mul(b352, b484);
    unsigned b585 = stwo_m31_mul(b355, b481);
    unsigned b586 = stwo_m31_add(b584, b585);
    unsigned b619 = stwo_m31_sub(b618, b586);
    unsigned b598 = stwo_m31_mul(b376, b508);
    unsigned b599 = stwo_m31_mul(b379, b505);
    unsigned b600 = stwo_m31_add(b598, b599);
    unsigned b620 = stwo_m31_sub(b619, b600);
    unsigned b621 = stwo_m31_add(b597, b620);
    unsigned b696 = stwo_m31_sub(b695, b621);
    unsigned b625 = stwo_m31_mul(b427, b571);
    unsigned b626 = stwo_m31_mul(b430, b568);
    unsigned b627 = stwo_m31_add(b625, b626);
    unsigned b628 = stwo_m31_mul(b433, b565);
    unsigned b629 = stwo_m31_add(b627, b628);
    unsigned b630 = stwo_m31_mul(b436, b562);
    unsigned b631 = stwo_m31_add(b629, b630);
    unsigned b632 = stwo_m31_mul(b439, b559);
    unsigned b633 = stwo_m31_add(b631, b632);
    unsigned b634 = stwo_m31_mul(b442, b556);
    unsigned b635 = stwo_m31_add(b633, b634);
    unsigned b639 = stwo_m31_add(b421, b445);
    unsigned b642 = stwo_m31_add(b553, b577);
    unsigned b643 = stwo_m31_mul(b639, b642);
    unsigned b640 = stwo_m31_add(b424, b448);
    unsigned b641 = stwo_m31_add(b550, b574);
    unsigned b644 = stwo_m31_mul(b640, b641);
    unsigned b645 = stwo_m31_add(b643, b644);
    unsigned b622 = stwo_m31_mul(b421, b553);
    unsigned b623 = stwo_m31_mul(b424, b550);
    unsigned b624 = stwo_m31_add(b622, b623);
    unsigned b646 = stwo_m31_sub(b645, b624);
    unsigned b636 = stwo_m31_mul(b445, b577);
    unsigned b637 = stwo_m31_mul(b448, b574);
    unsigned b638 = stwo_m31_add(b636, b637);
    unsigned b647 = stwo_m31_sub(b646, b638);
    unsigned b648 = stwo_m31_add(b635, b647);
    unsigned b697 = stwo_m31_sub(b696, b648);
    unsigned b698 = stwo_m31_add(b611, b697);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 293u, row_index, 0);
    unsigned b266 = base_params[144u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b267 = stwo_m31_mul(b266, b21);
    unsigned b268 = stwo_m31_add(b144, b267);
    unsigned b716 = stwo_m31_mul(b119, b268);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b263 = base_params[143u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b218 = base_params[128u];
    unsigned b219 = stwo_m31_mul(b144, b218);
    unsigned b220 = stwo_m31_sub(b20, b219);
    unsigned b264 = stwo_m31_mul(b263, b220);
    unsigned b265 = stwo_m31_add(b19, b264);
    unsigned b717 = stwo_m31_mul(b120, b265);
    unsigned b718 = stwo_m31_add(b716, b717);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 292u, row_index, 0);
    unsigned b260 = base_params[142u];
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b261 = stwo_m31_mul(b260, b18);
    unsigned b262 = stwo_m31_add(b143, b261);
    unsigned b719 = stwo_m31_mul(b121, b262);
    unsigned b720 = stwo_m31_add(b718, b719);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 291u, row_index, 0);
    unsigned b257 = base_params[141u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b215 = base_params[127u];
    unsigned b216 = stwo_m31_mul(b143, b215);
    unsigned b217 = stwo_m31_sub(b17, b216);
    unsigned b258 = stwo_m31_mul(b257, b217);
    unsigned b259 = stwo_m31_add(b142, b258);
    unsigned b721 = stwo_m31_mul(b122, b259);
    unsigned b722 = stwo_m31_add(b720, b721);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b254 = base_params[140u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b212 = base_params[126u];
    unsigned b213 = stwo_m31_mul(b142, b212);
    unsigned b214 = stwo_m31_sub(b16, b213);
    unsigned b255 = stwo_m31_mul(b254, b214);
    unsigned b256 = stwo_m31_add(b15, b255);
    unsigned b723 = stwo_m31_mul(b123, b256);
    unsigned b724 = stwo_m31_add(b722, b723);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 267u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 290u, row_index, 0);
    unsigned b251 = base_params[139u];
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b252 = stwo_m31_mul(b251, b14);
    unsigned b253 = stwo_m31_add(b141, b252);
    unsigned b725 = stwo_m31_mul(b124, b253);
    unsigned b726 = stwo_m31_add(b724, b725);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 270u, row_index, 0);
    unsigned b766 = stwo_m31_add(b111, b127);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 288u, row_index, 0);
    unsigned b242 = base_params[136u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b243 = stwo_m31_mul(b242, b10);
    unsigned b244 = stwo_m31_add(b139, b243);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 298u, row_index, 0);
    unsigned b311 = base_params[162u];
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b312 = stwo_m31_mul(b311, b32);
    unsigned b313 = stwo_m31_add(b149, b312);
    unsigned b781 = stwo_m31_add(b244, b313);
    unsigned b787 = stwo_m31_mul(b766, b781);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 271u, row_index, 0);
    unsigned b767 = stwo_m31_add(b112, b128);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b239 = base_params[135u];
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b203 = base_params[123u];
    unsigned b204 = stwo_m31_mul(b139, b203);
    unsigned b205 = stwo_m31_sub(b9, b204);
    unsigned b240 = stwo_m31_mul(b239, b205);
    unsigned b241 = stwo_m31_add(b8, b240);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b308 = base_params[161u];
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b281 = base_params[149u];
    unsigned b282 = stwo_m31_mul(b149, b281);
    unsigned b283 = stwo_m31_sub(b31, b282);
    unsigned b309 = stwo_m31_mul(b308, b283);
    unsigned b310 = stwo_m31_add(b30, b309);
    unsigned b780 = stwo_m31_add(b241, b310);
    unsigned b788 = stwo_m31_mul(b767, b780);
    unsigned b789 = stwo_m31_add(b787, b788);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 272u, row_index, 0);
    unsigned b768 = stwo_m31_add(b113, b129);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 287u, row_index, 0);
    unsigned b236 = base_params[134u];
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b237 = stwo_m31_mul(b236, b7);
    unsigned b238 = stwo_m31_add(b138, b237);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 297u, row_index, 0);
    unsigned b305 = base_params[160u];
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b306 = stwo_m31_mul(b305, b29);
    unsigned b307 = stwo_m31_add(b148, b306);
    unsigned b779 = stwo_m31_add(b238, b307);
    unsigned b790 = stwo_m31_mul(b768, b779);
    unsigned b791 = stwo_m31_add(b789, b790);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 257u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 273u, row_index, 0);
    unsigned b769 = stwo_m31_add(b114, b130);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 286u, row_index, 0);
    unsigned b233 = base_params[133u];
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b200 = base_params[122u];
    unsigned b201 = stwo_m31_mul(b138, b200);
    unsigned b202 = stwo_m31_sub(b6, b201);
    unsigned b234 = stwo_m31_mul(b233, b202);
    unsigned b235 = stwo_m31_add(b137, b234);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 296u, row_index, 0);
    unsigned b302 = base_params[159u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b278 = base_params[148u];
    unsigned b279 = stwo_m31_mul(b148, b278);
    unsigned b280 = stwo_m31_sub(b28, b279);
    unsigned b303 = stwo_m31_mul(b302, b280);
    unsigned b304 = stwo_m31_add(b147, b303);
    unsigned b778 = stwo_m31_add(b235, b304);
    unsigned b792 = stwo_m31_mul(b769, b778);
    unsigned b793 = stwo_m31_add(b791, b792);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 274u, row_index, 0);
    unsigned b770 = stwo_m31_add(b115, b131);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b230 = base_params[132u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b197 = base_params[121u];
    unsigned b198 = stwo_m31_mul(b137, b197);
    unsigned b199 = stwo_m31_sub(b5, b198);
    unsigned b231 = stwo_m31_mul(b230, b199);
    unsigned b232 = stwo_m31_add(b4, b231);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b299 = base_params[158u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b275 = base_params[147u];
    unsigned b276 = stwo_m31_mul(b147, b275);
    unsigned b277 = stwo_m31_sub(b27, b276);
    unsigned b300 = stwo_m31_mul(b299, b277);
    unsigned b301 = stwo_m31_add(b26, b300);
    unsigned b777 = stwo_m31_add(b232, b301);
    unsigned b794 = stwo_m31_mul(b770, b777);
    unsigned b795 = stwo_m31_add(b793, b794);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 275u, row_index, 0);
    unsigned b771 = stwo_m31_add(b116, b132);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 285u, row_index, 0);
    unsigned b227 = base_params[131u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b228 = stwo_m31_mul(b227, b3);
    unsigned b229 = stwo_m31_add(b136, b228);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 295u, row_index, 0);
    unsigned b296 = base_params[157u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b297 = stwo_m31_mul(b296, b25);
    unsigned b298 = stwo_m31_add(b146, b297);
    unsigned b776 = stwo_m31_add(b229, b298);
    unsigned b796 = stwo_m31_mul(b771, b776);
    unsigned b797 = stwo_m31_add(b795, b796);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 268u, row_index, 0);
    unsigned b764 = stwo_m31_add(b109, b125);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 276u, row_index, 0);
    unsigned b772 = stwo_m31_add(b117, b133);
    unsigned b801 = stwo_m31_add(b764, b772);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 284u, row_index, 0);
    unsigned b224 = base_params[130u];
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b194 = base_params[120u];
    unsigned b195 = stwo_m31_mul(b136, b194);
    unsigned b196 = stwo_m31_sub(b2, b195);
    unsigned b225 = stwo_m31_mul(b224, b196);
    unsigned b226 = stwo_m31_add(b135, b225);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 294u, row_index, 0);
    unsigned b293 = base_params[156u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b272 = base_params[146u];
    unsigned b273 = stwo_m31_mul(b146, b272);
    unsigned b274 = stwo_m31_sub(b24, b273);
    unsigned b294 = stwo_m31_mul(b293, b274);
    unsigned b295 = stwo_m31_add(b145, b294);
    unsigned b775 = stwo_m31_add(b226, b295);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 289u, row_index, 0);
    unsigned b248 = base_params[138u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b209 = base_params[125u];
    unsigned b210 = stwo_m31_mul(b141, b209);
    unsigned b211 = stwo_m31_sub(b13, b210);
    unsigned b249 = stwo_m31_mul(b248, b211);
    unsigned b250 = stwo_m31_add(b140, b249);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 299u, row_index, 0);
    unsigned b317 = base_params[164u];
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 300u, row_index, 0);
    unsigned b287 = base_params[151u];
    unsigned b288 = stwo_m31_mul(b151, b287);
    unsigned b289 = stwo_m31_sub(b35, b288);
    unsigned b318 = stwo_m31_mul(b317, b289);
    unsigned b319 = stwo_m31_add(b150, b318);
    unsigned b783 = stwo_m31_add(b250, b319);
    unsigned b804 = stwo_m31_add(b775, b783);
    unsigned b805 = stwo_m31_mul(b801, b804);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 269u, row_index, 0);
    unsigned b765 = stwo_m31_add(b110, b126);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 277u, row_index, 0);
    unsigned b773 = stwo_m31_add(b118, b134);
    unsigned b802 = stwo_m31_add(b765, b773);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b221 = base_params[129u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b191 = base_params[119u];
    unsigned b192 = stwo_m31_mul(b135, b191);
    unsigned b193 = stwo_m31_sub(b1, b192);
    unsigned b222 = stwo_m31_mul(b221, b193);
    unsigned b223 = stwo_m31_add(b0, b222);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b290 = base_params[155u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b269 = base_params[145u];
    unsigned b270 = stwo_m31_mul(b145, b269);
    unsigned b271 = stwo_m31_sub(b23, b270);
    unsigned b291 = stwo_m31_mul(b290, b271);
    unsigned b292 = stwo_m31_add(b22, b291);
    unsigned b774 = stwo_m31_add(b223, b292);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b245 = base_params[137u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b206 = base_params[124u];
    unsigned b207 = stwo_m31_mul(b140, b206);
    unsigned b208 = stwo_m31_sub(b12, b207);
    unsigned b246 = stwo_m31_mul(b245, b208);
    unsigned b247 = stwo_m31_add(b11, b246);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b314 = base_params[163u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b284 = base_params[150u];
    unsigned b285 = stwo_m31_mul(b150, b284);
    unsigned b286 = stwo_m31_sub(b34, b285);
    unsigned b315 = stwo_m31_mul(b314, b286);
    unsigned b316 = stwo_m31_add(b33, b315);
    unsigned b782 = stwo_m31_add(b247, b316);
    unsigned b803 = stwo_m31_add(b774, b782);
    unsigned b806 = stwo_m31_mul(b802, b803);
    unsigned b807 = stwo_m31_add(b805, b806);
    unsigned b784 = stwo_m31_mul(b764, b775);
    unsigned b785 = stwo_m31_mul(b765, b774);
    unsigned b786 = stwo_m31_add(b784, b785);
    unsigned b808 = stwo_m31_sub(b807, b786);
    unsigned b798 = stwo_m31_mul(b772, b783);
    unsigned b799 = stwo_m31_mul(b773, b782);
    unsigned b800 = stwo_m31_add(b798, b799);
    unsigned b809 = stwo_m31_sub(b808, b800);
    unsigned b810 = stwo_m31_add(b797, b809);
    unsigned b702 = stwo_m31_mul(b111, b244);
    unsigned b703 = stwo_m31_mul(b112, b241);
    unsigned b704 = stwo_m31_add(b702, b703);
    unsigned b705 = stwo_m31_mul(b113, b238);
    unsigned b706 = stwo_m31_add(b704, b705);
    unsigned b707 = stwo_m31_mul(b114, b235);
    unsigned b708 = stwo_m31_add(b706, b707);
    unsigned b709 = stwo_m31_mul(b115, b232);
    unsigned b710 = stwo_m31_add(b708, b709);
    unsigned b711 = stwo_m31_mul(b116, b229);
    unsigned b712 = stwo_m31_add(b710, b711);
    unsigned b727 = stwo_m31_add(b109, b117);
    unsigned b730 = stwo_m31_add(b226, b250);
    unsigned b731 = stwo_m31_mul(b727, b730);
    unsigned b728 = stwo_m31_add(b110, b118);
    unsigned b729 = stwo_m31_add(b223, b247);
    unsigned b732 = stwo_m31_mul(b728, b729);
    unsigned b733 = stwo_m31_add(b731, b732);
    unsigned b699 = stwo_m31_mul(b109, b226);
    unsigned b700 = stwo_m31_mul(b110, b223);
    unsigned b701 = stwo_m31_add(b699, b700);
    unsigned b734 = stwo_m31_sub(b733, b701);
    unsigned b713 = stwo_m31_mul(b117, b250);
    unsigned b714 = stwo_m31_mul(b118, b247);
    unsigned b715 = stwo_m31_add(b713, b714);
    unsigned b735 = stwo_m31_sub(b734, b715);
    unsigned b736 = stwo_m31_add(b712, b735);
    unsigned b811 = stwo_m31_sub(b810, b736);
    unsigned b740 = stwo_m31_mul(b127, b313);
    unsigned b741 = stwo_m31_mul(b128, b310);
    unsigned b742 = stwo_m31_add(b740, b741);
    unsigned b743 = stwo_m31_mul(b129, b307);
    unsigned b744 = stwo_m31_add(b742, b743);
    unsigned b745 = stwo_m31_mul(b130, b304);
    unsigned b746 = stwo_m31_add(b744, b745);
    unsigned b747 = stwo_m31_mul(b131, b301);
    unsigned b748 = stwo_m31_add(b746, b747);
    unsigned b749 = stwo_m31_mul(b132, b298);
    unsigned b750 = stwo_m31_add(b748, b749);
    unsigned b754 = stwo_m31_add(b125, b133);
    unsigned b757 = stwo_m31_add(b295, b319);
    unsigned b758 = stwo_m31_mul(b754, b757);
    unsigned b755 = stwo_m31_add(b126, b134);
    unsigned b756 = stwo_m31_add(b292, b316);
    unsigned b759 = stwo_m31_mul(b755, b756);
    unsigned b760 = stwo_m31_add(b758, b759);
    unsigned b737 = stwo_m31_mul(b125, b295);
    unsigned b738 = stwo_m31_mul(b126, b292);
    unsigned b739 = stwo_m31_add(b737, b738);
    unsigned b761 = stwo_m31_sub(b760, b739);
    unsigned b751 = stwo_m31_mul(b133, b319);
    unsigned b752 = stwo_m31_mul(b134, b316);
    unsigned b753 = stwo_m31_add(b751, b752);
    unsigned b762 = stwo_m31_sub(b761, b753);
    unsigned b763 = stwo_m31_add(b750, b762);
    unsigned b812 = stwo_m31_sub(b811, b763);
    unsigned b813 = stwo_m31_add(b726, b812);
    unsigned b815 = stwo_m31_sub(b698, b813);
    unsigned b816 = stwo_m31_add(b814, b815);
    unsigned b817 = base_params[378u];
    unsigned b818 = stwo_m31_mul(b816, b817);
    unsigned b819 = stwo_m31_sub(b189, b818);
    unsigned b190 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b819, b190, b190, b190 };
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
