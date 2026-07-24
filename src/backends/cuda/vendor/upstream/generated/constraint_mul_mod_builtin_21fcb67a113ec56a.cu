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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_e18ff78e8d2b1add(
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
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 401u, row_index, 0);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 400u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b389 = base_params[207u];
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 314u, row_index, 0);
    unsigned b359 = base_params[197u];
    unsigned b360 = stwo_m31_mul(b156, b359);
    unsigned b361 = stwo_m31_sub(b51, b360);
    unsigned b390 = stwo_m31_mul(b389, b361);
    unsigned b391 = stwo_m31_add(b50, b390);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 337u, row_index, 0);
    unsigned b530 = base_params[264u];
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    unsigned b531 = stwo_m31_mul(b530, b93);
    unsigned b532 = stwo_m31_add(b175, b531);
    unsigned b590 = stwo_m31_mul(b391, b532);
    unsigned b392 = base_params[208u];
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 315u, row_index, 0);
    unsigned b362 = base_params[198u];
    unsigned b363 = stwo_m31_mul(b157, b362);
    unsigned b364 = stwo_m31_sub(b52, b363);
    unsigned b393 = stwo_m31_mul(b392, b364);
    unsigned b394 = stwo_m31_add(b156, b393);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 336u, row_index, 0);
    unsigned b527 = base_params[263u];
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b494 = base_params[252u];
    unsigned b495 = stwo_m31_mul(b175, b494);
    unsigned b496 = stwo_m31_sub(b92, b495);
    unsigned b528 = stwo_m31_mul(b527, b496);
    unsigned b529 = stwo_m31_add(b174, b528);
    unsigned b591 = stwo_m31_mul(b394, b529);
    unsigned b592 = stwo_m31_add(b590, b591);
    unsigned b395 = base_params[209u];
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b396 = stwo_m31_mul(b395, b53);
    unsigned b397 = stwo_m31_add(b157, b396);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    unsigned b524 = base_params[262u];
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b491 = base_params[251u];
    unsigned b492 = stwo_m31_mul(b174, b491);
    unsigned b493 = stwo_m31_sub(b91, b492);
    unsigned b525 = stwo_m31_mul(b524, b493);
    unsigned b526 = stwo_m31_add(b90, b525);
    unsigned b593 = stwo_m31_mul(b397, b526);
    unsigned b594 = stwo_m31_add(b592, b593);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b398 = base_params[210u];
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 316u, row_index, 0);
    unsigned b365 = base_params[199u];
    unsigned b366 = stwo_m31_mul(b158, b365);
    unsigned b367 = stwo_m31_sub(b55, b366);
    unsigned b399 = stwo_m31_mul(b398, b367);
    unsigned b400 = stwo_m31_add(b54, b399);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 335u, row_index, 0);
    unsigned b521 = base_params[261u];
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    unsigned b522 = stwo_m31_mul(b521, b89);
    unsigned b523 = stwo_m31_add(b173, b522);
    unsigned b595 = stwo_m31_mul(b400, b523);
    unsigned b596 = stwo_m31_add(b594, b595);
    unsigned b401 = base_params[211u];
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 317u, row_index, 0);
    unsigned b368 = base_params[200u];
    unsigned b369 = stwo_m31_mul(b159, b368);
    unsigned b370 = stwo_m31_sub(b56, b369);
    unsigned b402 = stwo_m31_mul(b401, b370);
    unsigned b403 = stwo_m31_add(b158, b402);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 334u, row_index, 0);
    unsigned b518 = base_params[260u];
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b488 = base_params[250u];
    unsigned b489 = stwo_m31_mul(b173, b488);
    unsigned b490 = stwo_m31_sub(b88, b489);
    unsigned b519 = stwo_m31_mul(b518, b490);
    unsigned b520 = stwo_m31_add(b172, b519);
    unsigned b597 = stwo_m31_mul(b403, b520);
    unsigned b598 = stwo_m31_add(b596, b597);
    unsigned b404 = base_params[212u];
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b405 = stwo_m31_mul(b404, b57);
    unsigned b406 = stwo_m31_add(b159, b405);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    unsigned b515 = base_params[259u];
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b485 = base_params[249u];
    unsigned b486 = stwo_m31_mul(b172, b485);
    unsigned b487 = stwo_m31_sub(b87, b486);
    unsigned b516 = stwo_m31_mul(b515, b487);
    unsigned b517 = stwo_m31_add(b86, b516);
    unsigned b599 = stwo_m31_mul(b406, b517);
    unsigned b600 = stwo_m31_add(b598, b599);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b335 = base_params[189u];
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 309u, row_index, 0);
    unsigned b314 = base_params[176u];
    unsigned b315 = stwo_m31_mul(b151, b314);
    unsigned b316 = stwo_m31_sub(b40, b315);
    unsigned b336 = stwo_m31_mul(b335, b316);
    unsigned b337 = stwo_m31_add(b39, b336);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b413 = base_params[215u];
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 319u, row_index, 0);
    unsigned b374 = base_params[202u];
    unsigned b375 = stwo_m31_mul(b161, b374);
    unsigned b376 = stwo_m31_sub(b62, b375);
    unsigned b414 = stwo_m31_mul(b413, b376);
    unsigned b415 = stwo_m31_add(b61, b414);
    unsigned b630 = stwo_m31_add(b337, b415);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 332u, row_index, 0);
    unsigned b476 = base_params[246u];
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b477 = stwo_m31_mul(b476, b82);
    unsigned b478 = stwo_m31_add(b170, b477);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 342u, row_index, 0);
    unsigned b554 = base_params[272u];
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b555 = stwo_m31_mul(b554, b104);
    unsigned b556 = stwo_m31_add(b180, b555);
    unsigned b645 = stwo_m31_add(b478, b556);
    unsigned b651 = stwo_m31_mul(b630, b645);
    unsigned b338 = base_params[190u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 310u, row_index, 0);
    unsigned b317 = base_params[177u];
    unsigned b318 = stwo_m31_mul(b152, b317);
    unsigned b319 = stwo_m31_sub(b41, b318);
    unsigned b339 = stwo_m31_mul(b338, b319);
    unsigned b340 = stwo_m31_add(b151, b339);
    unsigned b416 = base_params[216u];
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 320u, row_index, 0);
    unsigned b377 = base_params[203u];
    unsigned b378 = stwo_m31_mul(b162, b377);
    unsigned b379 = stwo_m31_sub(b63, b378);
    unsigned b417 = stwo_m31_mul(b416, b379);
    unsigned b418 = stwo_m31_add(b161, b417);
    unsigned b631 = stwo_m31_add(b340, b418);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 331u, row_index, 0);
    unsigned b473 = base_params[245u];
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b449 = base_params[231u];
    unsigned b450 = stwo_m31_mul(b170, b449);
    unsigned b451 = stwo_m31_sub(b81, b450);
    unsigned b474 = stwo_m31_mul(b473, b451);
    unsigned b475 = stwo_m31_add(b169, b474);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 341u, row_index, 0);
    unsigned b551 = base_params[271u];
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b509 = base_params[257u];
    unsigned b510 = stwo_m31_mul(b180, b509);
    unsigned b511 = stwo_m31_sub(b103, b510);
    unsigned b552 = stwo_m31_mul(b551, b511);
    unsigned b553 = stwo_m31_add(b179, b552);
    unsigned b644 = stwo_m31_add(b475, b553);
    unsigned b652 = stwo_m31_mul(b631, b644);
    unsigned b653 = stwo_m31_add(b651, b652);
    unsigned b341 = base_params[191u];
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b342 = stwo_m31_mul(b341, b42);
    unsigned b343 = stwo_m31_add(b152, b342);
    unsigned b419 = base_params[217u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    unsigned b420 = stwo_m31_mul(b419, b64);
    unsigned b421 = stwo_m31_add(b162, b420);
    unsigned b632 = stwo_m31_add(b343, b421);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b470 = base_params[244u];
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b446 = base_params[230u];
    unsigned b447 = stwo_m31_mul(b169, b446);
    unsigned b448 = stwo_m31_sub(b80, b447);
    unsigned b471 = stwo_m31_mul(b470, b448);
    unsigned b472 = stwo_m31_add(b79, b471);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b548 = base_params[270u];
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b506 = base_params[256u];
    unsigned b507 = stwo_m31_mul(b179, b506);
    unsigned b508 = stwo_m31_sub(b102, b507);
    unsigned b549 = stwo_m31_mul(b548, b508);
    unsigned b550 = stwo_m31_add(b101, b549);
    unsigned b643 = stwo_m31_add(b472, b550);
    unsigned b654 = stwo_m31_mul(b632, b643);
    unsigned b655 = stwo_m31_add(b653, b654);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b344 = base_params[192u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 311u, row_index, 0);
    unsigned b320 = base_params[178u];
    unsigned b321 = stwo_m31_mul(b153, b320);
    unsigned b322 = stwo_m31_sub(b44, b321);
    unsigned b345 = stwo_m31_mul(b344, b322);
    unsigned b346 = stwo_m31_add(b43, b345);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    unsigned b422 = base_params[218u];
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 321u, row_index, 0);
    unsigned b380 = base_params[204u];
    unsigned b381 = stwo_m31_mul(b163, b380);
    unsigned b382 = stwo_m31_sub(b66, b381);
    unsigned b423 = stwo_m31_mul(b422, b382);
    unsigned b424 = stwo_m31_add(b65, b423);
    unsigned b633 = stwo_m31_add(b346, b424);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 330u, row_index, 0);
    unsigned b467 = base_params[243u];
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b468 = stwo_m31_mul(b467, b78);
    unsigned b469 = stwo_m31_add(b168, b468);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 340u, row_index, 0);
    unsigned b545 = base_params[269u];
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    unsigned b546 = stwo_m31_mul(b545, b100);
    unsigned b547 = stwo_m31_add(b178, b546);
    unsigned b642 = stwo_m31_add(b469, b547);
    unsigned b656 = stwo_m31_mul(b633, b642);
    unsigned b657 = stwo_m31_add(b655, b656);
    unsigned b347 = base_params[193u];
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 312u, row_index, 0);
    unsigned b323 = base_params[179u];
    unsigned b324 = stwo_m31_mul(b154, b323);
    unsigned b325 = stwo_m31_sub(b45, b324);
    unsigned b348 = stwo_m31_mul(b347, b325);
    unsigned b349 = stwo_m31_add(b153, b348);
    unsigned b425 = base_params[219u];
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 322u, row_index, 0);
    unsigned b383 = base_params[205u];
    unsigned b384 = stwo_m31_mul(b164, b383);
    unsigned b385 = stwo_m31_sub(b67, b384);
    unsigned b426 = stwo_m31_mul(b425, b385);
    unsigned b427 = stwo_m31_add(b163, b426);
    unsigned b634 = stwo_m31_add(b349, b427);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 329u, row_index, 0);
    unsigned b464 = base_params[242u];
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b443 = base_params[229u];
    unsigned b444 = stwo_m31_mul(b168, b443);
    unsigned b445 = stwo_m31_sub(b77, b444);
    unsigned b465 = stwo_m31_mul(b464, b445);
    unsigned b466 = stwo_m31_add(b167, b465);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 339u, row_index, 0);
    unsigned b542 = base_params[268u];
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b503 = base_params[255u];
    unsigned b504 = stwo_m31_mul(b178, b503);
    unsigned b505 = stwo_m31_sub(b99, b504);
    unsigned b543 = stwo_m31_mul(b542, b505);
    unsigned b544 = stwo_m31_add(b177, b543);
    unsigned b641 = stwo_m31_add(b466, b544);
    unsigned b658 = stwo_m31_mul(b634, b641);
    unsigned b659 = stwo_m31_add(b657, b658);
    unsigned b350 = base_params[194u];
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b351 = stwo_m31_mul(b350, b46);
    unsigned b352 = stwo_m31_add(b154, b351);
    unsigned b428 = base_params[220u];
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    unsigned b429 = stwo_m31_mul(b428, b68);
    unsigned b430 = stwo_m31_add(b164, b429);
    unsigned b635 = stwo_m31_add(b352, b430);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b461 = base_params[241u];
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b440 = base_params[228u];
    unsigned b441 = stwo_m31_mul(b167, b440);
    unsigned b442 = stwo_m31_sub(b76, b441);
    unsigned b462 = stwo_m31_mul(b461, b442);
    unsigned b463 = stwo_m31_add(b75, b462);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    unsigned b539 = base_params[267u];
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b500 = base_params[254u];
    unsigned b501 = stwo_m31_mul(b177, b500);
    unsigned b502 = stwo_m31_sub(b98, b501);
    unsigned b540 = stwo_m31_mul(b539, b502);
    unsigned b541 = stwo_m31_add(b97, b540);
    unsigned b640 = stwo_m31_add(b463, b541);
    unsigned b660 = stwo_m31_mul(b635, b640);
    unsigned b661 = stwo_m31_add(b659, b660);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b329 = base_params[187u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 308u, row_index, 0);
    unsigned b311 = base_params[175u];
    unsigned b312 = stwo_m31_mul(b150, b311);
    unsigned b313 = stwo_m31_sub(b37, b312);
    unsigned b330 = stwo_m31_mul(b329, b313);
    unsigned b331 = stwo_m31_add(b36, b330);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b407 = base_params[213u];
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 318u, row_index, 0);
    unsigned b371 = base_params[201u];
    unsigned b372 = stwo_m31_mul(b160, b371);
    unsigned b373 = stwo_m31_sub(b59, b372);
    unsigned b408 = stwo_m31_mul(b407, b373);
    unsigned b409 = stwo_m31_add(b58, b408);
    unsigned b628 = stwo_m31_add(b331, b409);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b353 = base_params[195u];
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 313u, row_index, 0);
    unsigned b326 = base_params[180u];
    unsigned b327 = stwo_m31_mul(b155, b326);
    unsigned b328 = stwo_m31_sub(b48, b327);
    unsigned b354 = stwo_m31_mul(b353, b328);
    unsigned b355 = stwo_m31_add(b47, b354);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b431 = base_params[221u];
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 323u, row_index, 0);
    unsigned b386 = base_params[206u];
    unsigned b387 = stwo_m31_mul(b165, b386);
    unsigned b388 = stwo_m31_sub(b70, b387);
    unsigned b432 = stwo_m31_mul(b431, b388);
    unsigned b433 = stwo_m31_add(b69, b432);
    unsigned b636 = stwo_m31_add(b355, b433);
    unsigned b665 = stwo_m31_add(b628, b636);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 328u, row_index, 0);
    unsigned b458 = base_params[240u];
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b459 = stwo_m31_mul(b458, b74);
    unsigned b460 = stwo_m31_add(b166, b459);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 338u, row_index, 0);
    unsigned b536 = base_params[266u];
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    unsigned b537 = stwo_m31_mul(b536, b96);
    unsigned b538 = stwo_m31_add(b176, b537);
    unsigned b639 = stwo_m31_add(b460, b538);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 333u, row_index, 0);
    unsigned b482 = base_params[248u];
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b483 = stwo_m31_mul(b482, b85);
    unsigned b484 = stwo_m31_add(b171, b483);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 343u, row_index, 0);
    unsigned b560 = base_params[274u];
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b561 = stwo_m31_mul(b560, b107);
    unsigned b562 = stwo_m31_add(b181, b561);
    unsigned b647 = stwo_m31_add(b484, b562);
    unsigned b668 = stwo_m31_add(b639, b647);
    unsigned b669 = stwo_m31_mul(b665, b668);
    unsigned b332 = base_params[188u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b333 = stwo_m31_mul(b332, b38);
    unsigned b334 = stwo_m31_add(b150, b333);
    unsigned b410 = base_params[214u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b411 = stwo_m31_mul(b410, b60);
    unsigned b412 = stwo_m31_add(b160, b411);
    unsigned b629 = stwo_m31_add(b334, b412);
    unsigned b356 = base_params[196u];
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b357 = stwo_m31_mul(b356, b49);
    unsigned b358 = stwo_m31_add(b155, b357);
    unsigned b434 = base_params[222u];
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b435 = stwo_m31_mul(b434, b71);
    unsigned b436 = stwo_m31_add(b165, b435);
    unsigned b637 = stwo_m31_add(b358, b436);
    unsigned b666 = stwo_m31_add(b629, b637);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b455 = base_params[239u];
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b437 = base_params[227u];
    unsigned b438 = stwo_m31_mul(b166, b437);
    unsigned b439 = stwo_m31_sub(b73, b438);
    unsigned b456 = stwo_m31_mul(b455, b439);
    unsigned b457 = stwo_m31_add(b72, b456);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    unsigned b533 = base_params[265u];
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b497 = base_params[253u];
    unsigned b498 = stwo_m31_mul(b176, b497);
    unsigned b499 = stwo_m31_sub(b95, b498);
    unsigned b534 = stwo_m31_mul(b533, b499);
    unsigned b535 = stwo_m31_add(b94, b534);
    unsigned b638 = stwo_m31_add(b457, b535);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b479 = base_params[247u];
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b452 = base_params[232u];
    unsigned b453 = stwo_m31_mul(b171, b452);
    unsigned b454 = stwo_m31_sub(b84, b453);
    unsigned b480 = stwo_m31_mul(b479, b454);
    unsigned b481 = stwo_m31_add(b83, b480);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b557 = base_params[273u];
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b512 = base_params[258u];
    unsigned b513 = stwo_m31_mul(b181, b512);
    unsigned b514 = stwo_m31_sub(b106, b513);
    unsigned b558 = stwo_m31_mul(b557, b514);
    unsigned b559 = stwo_m31_add(b105, b558);
    unsigned b646 = stwo_m31_add(b481, b559);
    unsigned b667 = stwo_m31_add(b638, b646);
    unsigned b670 = stwo_m31_mul(b666, b667);
    unsigned b671 = stwo_m31_add(b669, b670);
    unsigned b648 = stwo_m31_mul(b628, b639);
    unsigned b649 = stwo_m31_mul(b629, b638);
    unsigned b650 = stwo_m31_add(b648, b649);
    unsigned b672 = stwo_m31_sub(b671, b650);
    unsigned b662 = stwo_m31_mul(b636, b647);
    unsigned b663 = stwo_m31_mul(b637, b646);
    unsigned b664 = stwo_m31_add(b662, b663);
    unsigned b673 = stwo_m31_sub(b672, b664);
    unsigned b674 = stwo_m31_add(b661, b673);
    unsigned b566 = stwo_m31_mul(b337, b478);
    unsigned b567 = stwo_m31_mul(b340, b475);
    unsigned b568 = stwo_m31_add(b566, b567);
    unsigned b569 = stwo_m31_mul(b343, b472);
    unsigned b570 = stwo_m31_add(b568, b569);
    unsigned b571 = stwo_m31_mul(b346, b469);
    unsigned b572 = stwo_m31_add(b570, b571);
    unsigned b573 = stwo_m31_mul(b349, b466);
    unsigned b574 = stwo_m31_add(b572, b573);
    unsigned b575 = stwo_m31_mul(b352, b463);
    unsigned b576 = stwo_m31_add(b574, b575);
    unsigned b580 = stwo_m31_add(b331, b355);
    unsigned b583 = stwo_m31_add(b460, b484);
    unsigned b584 = stwo_m31_mul(b580, b583);
    unsigned b581 = stwo_m31_add(b334, b358);
    unsigned b582 = stwo_m31_add(b457, b481);
    unsigned b585 = stwo_m31_mul(b581, b582);
    unsigned b586 = stwo_m31_add(b584, b585);
    unsigned b563 = stwo_m31_mul(b331, b460);
    unsigned b564 = stwo_m31_mul(b334, b457);
    unsigned b565 = stwo_m31_add(b563, b564);
    unsigned b587 = stwo_m31_sub(b586, b565);
    unsigned b577 = stwo_m31_mul(b355, b484);
    unsigned b578 = stwo_m31_mul(b358, b481);
    unsigned b579 = stwo_m31_add(b577, b578);
    unsigned b588 = stwo_m31_sub(b587, b579);
    unsigned b589 = stwo_m31_add(b576, b588);
    unsigned b675 = stwo_m31_sub(b674, b589);
    unsigned b604 = stwo_m31_mul(b415, b556);
    unsigned b605 = stwo_m31_mul(b418, b553);
    unsigned b606 = stwo_m31_add(b604, b605);
    unsigned b607 = stwo_m31_mul(b421, b550);
    unsigned b608 = stwo_m31_add(b606, b607);
    unsigned b609 = stwo_m31_mul(b424, b547);
    unsigned b610 = stwo_m31_add(b608, b609);
    unsigned b611 = stwo_m31_mul(b427, b544);
    unsigned b612 = stwo_m31_add(b610, b611);
    unsigned b613 = stwo_m31_mul(b430, b541);
    unsigned b614 = stwo_m31_add(b612, b613);
    unsigned b618 = stwo_m31_add(b409, b433);
    unsigned b621 = stwo_m31_add(b538, b562);
    unsigned b622 = stwo_m31_mul(b618, b621);
    unsigned b619 = stwo_m31_add(b412, b436);
    unsigned b620 = stwo_m31_add(b535, b559);
    unsigned b623 = stwo_m31_mul(b619, b620);
    unsigned b624 = stwo_m31_add(b622, b623);
    unsigned b601 = stwo_m31_mul(b409, b538);
    unsigned b602 = stwo_m31_mul(b412, b535);
    unsigned b603 = stwo_m31_add(b601, b602);
    unsigned b625 = stwo_m31_sub(b624, b603);
    unsigned b615 = stwo_m31_mul(b433, b562);
    unsigned b616 = stwo_m31_mul(b436, b559);
    unsigned b617 = stwo_m31_add(b615, b616);
    unsigned b626 = stwo_m31_sub(b625, b617);
    unsigned b627 = stwo_m31_add(b614, b626);
    unsigned b676 = stwo_m31_sub(b675, b627);
    unsigned b677 = stwo_m31_add(b600, b676);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 268u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 297u, row_index, 0);
    unsigned b278 = base_params[160u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b279 = stwo_m31_mul(b278, b21);
    unsigned b280 = stwo_m31_add(b143, b279);
    unsigned b705 = stwo_m31_mul(b118, b280);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 269u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 296u, row_index, 0);
    unsigned b275 = base_params[159u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b242 = base_params[148u];
    unsigned b243 = stwo_m31_mul(b143, b242);
    unsigned b244 = stwo_m31_sub(b20, b243);
    unsigned b276 = stwo_m31_mul(b275, b244);
    unsigned b277 = stwo_m31_add(b142, b276);
    unsigned b706 = stwo_m31_mul(b119, b277);
    unsigned b707 = stwo_m31_add(b705, b706);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 270u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b272 = base_params[158u];
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b239 = base_params[147u];
    unsigned b240 = stwo_m31_mul(b142, b239);
    unsigned b241 = stwo_m31_sub(b19, b240);
    unsigned b273 = stwo_m31_mul(b272, b241);
    unsigned b274 = stwo_m31_add(b18, b273);
    unsigned b708 = stwo_m31_mul(b120, b274);
    unsigned b709 = stwo_m31_add(b707, b708);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 271u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 295u, row_index, 0);
    unsigned b269 = base_params[157u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b270 = stwo_m31_mul(b269, b17);
    unsigned b271 = stwo_m31_add(b141, b270);
    unsigned b710 = stwo_m31_mul(b121, b271);
    unsigned b711 = stwo_m31_add(b709, b710);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 272u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 294u, row_index, 0);
    unsigned b266 = base_params[156u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b236 = base_params[146u];
    unsigned b237 = stwo_m31_mul(b141, b236);
    unsigned b238 = stwo_m31_sub(b16, b237);
    unsigned b267 = stwo_m31_mul(b266, b238);
    unsigned b268 = stwo_m31_add(b140, b267);
    unsigned b712 = stwo_m31_mul(b122, b268);
    unsigned b713 = stwo_m31_add(b711, b712);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 273u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b263 = base_params[155u];
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b233 = base_params[145u];
    unsigned b234 = stwo_m31_mul(b140, b233);
    unsigned b235 = stwo_m31_sub(b15, b234);
    unsigned b264 = stwo_m31_mul(b263, b235);
    unsigned b265 = stwo_m31_add(b14, b264);
    unsigned b714 = stwo_m31_mul(b123, b265);
    unsigned b715 = stwo_m31_add(b713, b714);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 276u, row_index, 0);
    unsigned b745 = stwo_m31_add(b110, b126);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 292u, row_index, 0);
    unsigned b224 = base_params[142u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b225 = stwo_m31_mul(b224, b10);
    unsigned b226 = stwo_m31_add(b138, b225);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 302u, row_index, 0);
    unsigned b302 = base_params[168u];
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b303 = stwo_m31_mul(b302, b32);
    unsigned b304 = stwo_m31_add(b148, b303);
    unsigned b760 = stwo_m31_add(b226, b304);
    unsigned b766 = stwo_m31_mul(b745, b760);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 277u, row_index, 0);
    unsigned b746 = stwo_m31_add(b111, b127);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 291u, row_index, 0);
    unsigned b221 = base_params[141u];
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b197 = base_params[127u];
    unsigned b198 = stwo_m31_mul(b138, b197);
    unsigned b199 = stwo_m31_sub(b9, b198);
    unsigned b222 = stwo_m31_mul(b221, b199);
    unsigned b223 = stwo_m31_add(b137, b222);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 301u, row_index, 0);
    unsigned b299 = base_params[167u];
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b257 = base_params[153u];
    unsigned b258 = stwo_m31_mul(b148, b257);
    unsigned b259 = stwo_m31_sub(b31, b258);
    unsigned b300 = stwo_m31_mul(b299, b259);
    unsigned b301 = stwo_m31_add(b147, b300);
    unsigned b759 = stwo_m31_add(b223, b301);
    unsigned b767 = stwo_m31_mul(b746, b759);
    unsigned b768 = stwo_m31_add(b766, b767);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 278u, row_index, 0);
    unsigned b747 = stwo_m31_add(b112, b128);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b218 = base_params[140u];
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b194 = base_params[126u];
    unsigned b195 = stwo_m31_mul(b137, b194);
    unsigned b196 = stwo_m31_sub(b8, b195);
    unsigned b219 = stwo_m31_mul(b218, b196);
    unsigned b220 = stwo_m31_add(b7, b219);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b296 = base_params[166u];
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b254 = base_params[152u];
    unsigned b255 = stwo_m31_mul(b147, b254);
    unsigned b256 = stwo_m31_sub(b30, b255);
    unsigned b297 = stwo_m31_mul(b296, b256);
    unsigned b298 = stwo_m31_add(b29, b297);
    unsigned b758 = stwo_m31_add(b220, b298);
    unsigned b769 = stwo_m31_mul(b747, b758);
    unsigned b770 = stwo_m31_add(b768, b769);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 279u, row_index, 0);
    unsigned b748 = stwo_m31_add(b113, b129);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 290u, row_index, 0);
    unsigned b215 = base_params[139u];
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b216 = stwo_m31_mul(b215, b6);
    unsigned b217 = stwo_m31_add(b136, b216);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 300u, row_index, 0);
    unsigned b293 = base_params[165u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b294 = stwo_m31_mul(b293, b28);
    unsigned b295 = stwo_m31_add(b146, b294);
    unsigned b757 = stwo_m31_add(b217, b295);
    unsigned b771 = stwo_m31_mul(b748, b757);
    unsigned b772 = stwo_m31_add(b770, b771);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 280u, row_index, 0);
    unsigned b749 = stwo_m31_add(b114, b130);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 289u, row_index, 0);
    unsigned b212 = base_params[138u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b191 = base_params[125u];
    unsigned b192 = stwo_m31_mul(b136, b191);
    unsigned b193 = stwo_m31_sub(b5, b192);
    unsigned b213 = stwo_m31_mul(b212, b193);
    unsigned b214 = stwo_m31_add(b135, b213);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 299u, row_index, 0);
    unsigned b290 = base_params[164u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b251 = base_params[151u];
    unsigned b252 = stwo_m31_mul(b146, b251);
    unsigned b253 = stwo_m31_sub(b27, b252);
    unsigned b291 = stwo_m31_mul(b290, b253);
    unsigned b292 = stwo_m31_add(b145, b291);
    unsigned b756 = stwo_m31_add(b214, b292);
    unsigned b773 = stwo_m31_mul(b749, b756);
    unsigned b774 = stwo_m31_add(b772, b773);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 281u, row_index, 0);
    unsigned b750 = stwo_m31_add(b115, b131);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b209 = base_params[137u];
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b188 = base_params[124u];
    unsigned b189 = stwo_m31_mul(b135, b188);
    unsigned b190 = stwo_m31_sub(b4, b189);
    unsigned b210 = stwo_m31_mul(b209, b190);
    unsigned b211 = stwo_m31_add(b3, b210);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b287 = base_params[163u];
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b248 = base_params[150u];
    unsigned b249 = stwo_m31_mul(b145, b248);
    unsigned b250 = stwo_m31_sub(b26, b249);
    unsigned b288 = stwo_m31_mul(b287, b250);
    unsigned b289 = stwo_m31_add(b25, b288);
    unsigned b755 = stwo_m31_add(b211, b289);
    unsigned b775 = stwo_m31_mul(b750, b755);
    unsigned b776 = stwo_m31_add(b774, b775);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 274u, row_index, 0);
    unsigned b743 = stwo_m31_add(b108, b124);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 282u, row_index, 0);
    unsigned b751 = stwo_m31_add(b116, b132);
    unsigned b780 = stwo_m31_add(b743, b751);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 288u, row_index, 0);
    unsigned b206 = base_params[136u];
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b207 = stwo_m31_mul(b206, b2);
    unsigned b208 = stwo_m31_add(b134, b207);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 298u, row_index, 0);
    unsigned b284 = base_params[162u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b285 = stwo_m31_mul(b284, b24);
    unsigned b286 = stwo_m31_add(b144, b285);
    unsigned b754 = stwo_m31_add(b208, b286);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 293u, row_index, 0);
    unsigned b230 = base_params[144u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b231 = stwo_m31_mul(b230, b13);
    unsigned b232 = stwo_m31_add(b139, b231);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 303u, row_index, 0);
    unsigned b308 = base_params[170u];
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b309 = stwo_m31_mul(b308, b35);
    unsigned b310 = stwo_m31_add(b149, b309);
    unsigned b762 = stwo_m31_add(b232, b310);
    unsigned b783 = stwo_m31_add(b754, b762);
    unsigned b784 = stwo_m31_mul(b780, b783);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 275u, row_index, 0);
    unsigned b744 = stwo_m31_add(b109, b125);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 267u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 283u, row_index, 0);
    unsigned b752 = stwo_m31_add(b117, b133);
    unsigned b781 = stwo_m31_add(b744, b752);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b203 = base_params[135u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b185 = base_params[123u];
    unsigned b186 = stwo_m31_mul(b134, b185);
    unsigned b187 = stwo_m31_sub(b1, b186);
    unsigned b204 = stwo_m31_mul(b203, b187);
    unsigned b205 = stwo_m31_add(b0, b204);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b281 = base_params[161u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b245 = base_params[149u];
    unsigned b246 = stwo_m31_mul(b144, b245);
    unsigned b247 = stwo_m31_sub(b23, b246);
    unsigned b282 = stwo_m31_mul(b281, b247);
    unsigned b283 = stwo_m31_add(b22, b282);
    unsigned b753 = stwo_m31_add(b205, b283);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b227 = base_params[143u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b200 = base_params[128u];
    unsigned b201 = stwo_m31_mul(b139, b200);
    unsigned b202 = stwo_m31_sub(b12, b201);
    unsigned b228 = stwo_m31_mul(b227, b202);
    unsigned b229 = stwo_m31_add(b11, b228);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b305 = base_params[169u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b260 = base_params[154u];
    unsigned b261 = stwo_m31_mul(b149, b260);
    unsigned b262 = stwo_m31_sub(b34, b261);
    unsigned b306 = stwo_m31_mul(b305, b262);
    unsigned b307 = stwo_m31_add(b33, b306);
    unsigned b761 = stwo_m31_add(b229, b307);
    unsigned b782 = stwo_m31_add(b753, b761);
    unsigned b785 = stwo_m31_mul(b781, b782);
    unsigned b786 = stwo_m31_add(b784, b785);
    unsigned b763 = stwo_m31_mul(b743, b754);
    unsigned b764 = stwo_m31_mul(b744, b753);
    unsigned b765 = stwo_m31_add(b763, b764);
    unsigned b787 = stwo_m31_sub(b786, b765);
    unsigned b777 = stwo_m31_mul(b751, b762);
    unsigned b778 = stwo_m31_mul(b752, b761);
    unsigned b779 = stwo_m31_add(b777, b778);
    unsigned b788 = stwo_m31_sub(b787, b779);
    unsigned b789 = stwo_m31_add(b776, b788);
    unsigned b681 = stwo_m31_mul(b110, b226);
    unsigned b682 = stwo_m31_mul(b111, b223);
    unsigned b683 = stwo_m31_add(b681, b682);
    unsigned b684 = stwo_m31_mul(b112, b220);
    unsigned b685 = stwo_m31_add(b683, b684);
    unsigned b686 = stwo_m31_mul(b113, b217);
    unsigned b687 = stwo_m31_add(b685, b686);
    unsigned b688 = stwo_m31_mul(b114, b214);
    unsigned b689 = stwo_m31_add(b687, b688);
    unsigned b690 = stwo_m31_mul(b115, b211);
    unsigned b691 = stwo_m31_add(b689, b690);
    unsigned b695 = stwo_m31_add(b108, b116);
    unsigned b698 = stwo_m31_add(b208, b232);
    unsigned b699 = stwo_m31_mul(b695, b698);
    unsigned b696 = stwo_m31_add(b109, b117);
    unsigned b697 = stwo_m31_add(b205, b229);
    unsigned b700 = stwo_m31_mul(b696, b697);
    unsigned b701 = stwo_m31_add(b699, b700);
    unsigned b678 = stwo_m31_mul(b108, b208);
    unsigned b679 = stwo_m31_mul(b109, b205);
    unsigned b680 = stwo_m31_add(b678, b679);
    unsigned b702 = stwo_m31_sub(b701, b680);
    unsigned b692 = stwo_m31_mul(b116, b232);
    unsigned b693 = stwo_m31_mul(b117, b229);
    unsigned b694 = stwo_m31_add(b692, b693);
    unsigned b703 = stwo_m31_sub(b702, b694);
    unsigned b704 = stwo_m31_add(b691, b703);
    unsigned b790 = stwo_m31_sub(b789, b704);
    unsigned b719 = stwo_m31_mul(b126, b304);
    unsigned b720 = stwo_m31_mul(b127, b301);
    unsigned b721 = stwo_m31_add(b719, b720);
    unsigned b722 = stwo_m31_mul(b128, b298);
    unsigned b723 = stwo_m31_add(b721, b722);
    unsigned b724 = stwo_m31_mul(b129, b295);
    unsigned b725 = stwo_m31_add(b723, b724);
    unsigned b726 = stwo_m31_mul(b130, b292);
    unsigned b727 = stwo_m31_add(b725, b726);
    unsigned b728 = stwo_m31_mul(b131, b289);
    unsigned b729 = stwo_m31_add(b727, b728);
    unsigned b733 = stwo_m31_add(b124, b132);
    unsigned b736 = stwo_m31_add(b286, b310);
    unsigned b737 = stwo_m31_mul(b733, b736);
    unsigned b734 = stwo_m31_add(b125, b133);
    unsigned b735 = stwo_m31_add(b283, b307);
    unsigned b738 = stwo_m31_mul(b734, b735);
    unsigned b739 = stwo_m31_add(b737, b738);
    unsigned b716 = stwo_m31_mul(b124, b286);
    unsigned b717 = stwo_m31_mul(b125, b283);
    unsigned b718 = stwo_m31_add(b716, b717);
    unsigned b740 = stwo_m31_sub(b739, b718);
    unsigned b730 = stwo_m31_mul(b132, b310);
    unsigned b731 = stwo_m31_mul(b133, b307);
    unsigned b732 = stwo_m31_add(b730, b731);
    unsigned b741 = stwo_m31_sub(b740, b732);
    unsigned b742 = stwo_m31_add(b729, b741);
    unsigned b791 = stwo_m31_sub(b790, b742);
    unsigned b792 = stwo_m31_add(b715, b791);
    unsigned b793 = stwo_m31_sub(b677, b792);
    unsigned b794 = stwo_m31_add(b182, b793);
    unsigned b795 = base_params[402u];
    unsigned b796 = stwo_m31_mul(b794, b795);
    unsigned b797 = stwo_m31_sub(b183, b796);
    unsigned b184 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b797, b184, b184, b184 };
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
