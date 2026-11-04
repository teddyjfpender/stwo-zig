// Tensor-prover CUDA kernels (hot paths). See design/tensor-frontend/cuda.md
// for the residency plan, the fusion plan and the launch counts.
//
// Conventions: QM31 vectors are flat u32 arrays of 4 limbs per element
// (AoS, as the host QM31 slices, so a factor uploads with one memcpy); M31
// vectors are canonical u32. Multilinear variable 0 is the MSB of the index
// (field.zig): fold(r) maps f to f(lo) + r (f(hi) - f(lo)) with hi = lo + half.
//
// Every kernel is written in the phase style of tc_prelude.cuh and is run
// bit-for-bit on the CPU by `zig build test-cuda-emu`.
#pragma once
#include "tc_field.cuh"
#include "tc_blake2s.cuh"

namespace tc {

// ===========================================================================
// Sumcheck: fused fold-of-previous-round + round sums {s(0), s(2), s(3)}.
// ===========================================================================

static constexpr uint32_t SC_MAX_FACTORS = 4;

struct ScTerms {
    uint32_t n_factors, n_terms, deg, _pad;
    uint32_t term_len[4];
    uint32_t term_fac[4][3];
    qm coeff[4];
};

struct ScRound {
    uint64_t half_len;     // half of the current length
    uint64_t active;       // entries >= active are zero
    uint64_t work;         // min(half_len, active)
    uint64_t prev_half;    // fused fold: half of the previous length (0 = none)
    uint64_t prev_active;
    qm r;                  // challenge of the previous round (fused fold) / fold
};

struct Factors {
    uint32_t *f[SC_MAX_FACTORS];
};

// Factor i of the four held in registers, selected without indexing (a
// runtime index into a thread-local array forces it into local memory: the
// round kernel's former 224-B frame).
TC_HD uint32_t sc_sel(uint32_t i, uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3) {
    // branch-free mask select on values (no address is ever formed)
    const uint32_t m0 = 0u - (uint32_t)(i == 0), m1 = 0u - (uint32_t)(i == 1), m2 = 0u - (uint32_t)(i == 2), m3 = 0u - (uint32_t)(i == 3);
    return (x0 & m0) | (x1 & m1) | (x2 & m2) | (x3 & m3);
}
TC_HD qm sc_pick(const qm *cur, uint32_t i) {
    return qm{sc_sel(i, cur[0].a, cur[1].a, cur[2].a, cur[3].a), sc_sel(i, cur[0].b, cur[1].b, cur[2].b, cur[3].b),
              sc_sel(i, cur[0].c, cur[1].c, cur[2].c, cur[3].c), sc_sel(i, cur[0].d, cur[1].d, cur[2].d, cur[3].d)};
}

// Constant-trip loops (terms <= 4, factors per term <= 3) guarded by the
// runtime counts, so every array index is a compile-time constant after
// unrolling.
TC_HD qm sc_eval_terms(const ScTerms &t, const qm *cur) {
    qm v = qm_zero();
    TC_UNROLL
    for (uint32_t k = 0; k < 4; ++k) {
        if (k < t.n_terms) {
            qm prod = sc_pick(cur, t.term_fac[k][0]);
            TC_UNROLL
            for (uint32_t j = 1; j < 3; ++j)
                if (j < t.term_len[k]) prod = qm_mul(prod, sc_pick(cur, t.term_fac[k][j]));
            if (!qm_is_one(t.coeff[k])) prod = qm_mul(prod, t.coeff[k]);
            v = qm_add(v, prod);
        }
    }
    return v;
}

TC_HD qm sc_folded(const uint32_t *f, const ScRound &p, uint64_t y) {
    const qm lo = qm_load(f, y);
    const qm hi = (y + p.prev_half < p.prev_active) ? qm_load(f, y + p.prev_half) : qm_zero();
    return qm_add(lo, qm_mul(p.r, qm_sub(hi, lo)));
}

// One launch per round. Thread x (grid-stride) owns positions x and x + half
// of the folded vector: it reads the four previous positions x, x + half,
// x + 2 half, x + 3 half (prev_half = 2 half), folds, writes x and x + half
// back in place (no other thread touches them), and accumulates the round
// sums lazily. Blocks reduce in shared memory; the last block to finish
// (ticket counter) adds the block partials in block order and writes the 3
// QM31 to `result` (a host-mapped mailbox in CUDA): one launch, one 48-byte
// readback per round.
TC_GLOBAL tc_sc_round(Factors fs, ScTerms t, ScRound p, uint32_t *partials, uint32_t *counter, uint32_t *result) {
    TC_SHARED qm sh[3 * TC_TB];
    TC_SHARED uint32_t last;
    TC_THREADS
        qacc a0 = qacc_zero(), a2 = qacc_zero(), a3 = qacc_zero();
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t x = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; x < p.work; x += stride) {
            qm lo[SC_MAX_FACTORS], diff[SC_MAX_FACTORS], cur[SC_MAX_FACTORS];
            const bool has_hi = x + p.half_len < p.active;
            TC_UNROLL
            for (uint32_t j = 0; j < SC_MAX_FACTORS; ++j) {
                if (j >= t.n_factors) { lo[j] = diff[j] = cur[j] = qm_zero(); continue; }
                qm l, h;
                if (p.prev_half != 0) {
                    l = sc_folded(fs.f[j], p, x);
                    h = has_hi ? sc_folded(fs.f[j], p, x + p.half_len) : qm_zero();
                } else {
                    l = qm_load(fs.f[j], x);
                    h = has_hi ? qm_load(fs.f[j], x + p.half_len) : qm_zero();
                }
                lo[j] = l;
                diff[j] = qm_sub(h, l);
                cur[j] = l;
            }
            if (p.prev_half != 0) {
                TC_UNROLL
                for (uint32_t j = 0; j < SC_MAX_FACTORS; ++j) {
                    if (j >= t.n_factors) continue;
                    qm_store(fs.f[j], x, lo[j]);
                    if (has_hi) qm_store(fs.f[j], x + p.half_len, qm_add(lo[j], diff[j]));
                }
            }
            qacc_add(a0, sc_eval_terms(t, cur));
            TC_UNROLL
            for (uint32_t j = 0; j < SC_MAX_FACTORS; ++j) cur[j] = qm_add(qm_add(cur[j], diff[j]), diff[j]);
            qacc_add(a2, sc_eval_terms(t, cur));
            if (t.deg >= 3) {
                TC_UNROLL
                for (uint32_t j = 0; j < SC_MAX_FACTORS; ++j) cur[j] = qm_add(cur[j], diff[j]);
                qacc_add(a3, sc_eval_terms(t, cur));
            }
        }
        sh[3 * tid] = qacc_get(a0);
        sh[3 * tid + 1] = qacc_get(a2);
        sh[3 * tid + 2] = qacc_get(a3);
    TC_END_THREADS
    TC_SYNC();
    for (uint32_t s = TC_BLOCK_DIM >> 1; s > 0; s >>= 1) {
        TC_THREADS
            if (tid < s)
                for (uint32_t k = 0; k < 3; ++k) sh[3 * tid + k] = qm_add(sh[3 * tid + k], sh[3 * (tid + s) + k]);
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        if (tid == 0) {
            for (uint32_t k = 0; k < 3; ++k) qm_store(partials, 3 * TC_BLOCK_ID + k, sh[k]);
            TC_FENCE();
            last = (TC_ATOMIC_INC(counter) == TC_NBLOCKS - 1) ? 1u : 0u;
        }
    TC_END_THREADS
    TC_SYNC();
    TC_THREADS
        if (tid == 0 && last) {
            qacc s[3] = {qacc_zero(), qacc_zero(), qacc_zero()};
            const volatile uint32_t *vp = partials;
            for (uint32_t b = 0; b < TC_NBLOCKS; ++b) {
                TC_UNROLL
                for (uint32_t k = 0; k < 3; ++k) {
                    const uint64_t o = 4ull * (3 * b + k);
                    qacc_add(s[k], qm{vp[o], vp[o + 1], vp[o + 2], vp[o + 3]});
                }
            }
            TC_UNROLL
            for (uint32_t k = 0; k < 3; ++k) qm_store(result, k, qacc_get(s[k]));
            *counter = 0;  // ready for the next launch (stream-ordered)
        }
    TC_END_THREADS
}

// Plain fold f[x] = lo + r (hi - lo), x < work (the session's last round).
TC_GLOBAL tc_sc_fold(Factors fs, ScTerms t, ScRound p) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t x = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; x < p.work; x += stride) {
            const bool has_hi = x + p.half_len < p.active;
            for (uint32_t j = 0; j < t.n_factors; ++j) {
                const qm lo = qm_load(fs.f[j], x);
                const qm hi = has_hi ? qm_load(fs.f[j], x + p.half_len) : qm_zero();
                qm_store(fs.f[j], x, qm_add(lo, qm_mul(p.r, qm_sub(hi, lo))));
            }
        }
    TC_END_THREADS
}

// ===========================================================================
// eq tables: eq(point, i) * gamma, variable 0 = MSB. Two launches for any
// length: (1) two single-block in-place doublings build the high and low
// half tables (block 0: point[0 .. n_hi) scaled by gamma, block 1:
// point[n_hi .. n)); (2) an expansion writes hi[i >> n_lo] * lo[i & mask]
// (one QM31 mul per entry), optionally accumulating at an offset (batch
// claims: E = sum_c gamma_c eq(z_c, x - off_c)) and broadcasting over
// trailing free bits (FactorSpec.eq_prefix).
// ===========================================================================

TC_GLOBAL tc_eq_halves(const uint32_t *point, uint32_t n_hi, uint32_t n_lo, qm gamma, uint32_t *hi_tab, uint32_t *lo_tab) {
    const uint32_t blk = TC_BLOCK_ID;
    uint32_t *tab = blk == 0 ? hi_tab : lo_tab;
    const uint32_t m = blk == 0 ? n_hi : n_lo;
    const uint32_t *pt = blk == 0 ? point : point + 4 * n_hi;
    TC_THREADS
        if (tid == 0) qm_store(tab, 0, blk == 0 ? gamma : qm_one());
    TC_END_THREADS
    TC_SYNC();
    // vars from last to first: var m-1-k becomes bit k of the index
    for (uint32_t k = 0; k < m; ++k) {
        const uint64_t s = 1ull << k;
        const qm r = qm_load(pt, m - 1 - k);
        TC_THREADS
            for (uint64_t j = tid; j < s; j += TC_BLOCK_DIM) {
                const qm x = qm_load(tab, j);
                const qm xr = qm_mul(x, r);
                qm_store(tab, j + s, xr);
                qm_store(tab, j, qm_sub(x, xr));
            }
        TC_END_THREADS
        TC_SYNC();
    }
}

// out[off + i] (+)= hi[k >> n_lo] * lo[k & mask], k = i >> free_bits, i < count.
TC_GLOBAL tc_eq_expand(const uint32_t *hi_tab, const uint32_t *lo_tab, uint32_t n_lo, uint32_t free_bits, uint64_t count, uint64_t off, uint32_t accumulate, uint32_t *out) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        const uint64_t mask = (1ull << n_lo) - 1;
        for (uint64_t i = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; i < count; i += stride) {
            const uint64_t k = i >> free_bits;
            qm v = qm_mul(qm_load(hi_tab, k >> n_lo), qm_load(lo_tab, k & mask));
            if (accumulate) v = qm_add(v, qm_load(out, off + i));
            qm_store(out, off + i, v);
        }
    TC_END_THREADS
}

// Integer vector -> QM31 factor (base-field embedding), entries >= n are 0.
TC_GLOBAL tc_int_to_qm(const int32_t *v, uint64_t n, uint64_t len, uint32_t *out) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t i = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; i < len; i += stride)
            qm_store(out, i, qm{i < n ? m31_from_i32(v[i]) : 0u, 0, 0, 0});
    TC_END_THREADS
}

TC_GLOBAL tc_zero_u32(uint32_t *p, uint64_t n) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t i = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; i < n; i += stride) p[i] = 0;
    TC_END_THREADS
}

// ===========================================================================
// Weight passes (the int8 x QM31 folds of the PCS openings).
// ===========================================================================

// partials[chunk][g][c] = sum_{i in chunk} coeffs[g][i] * m[i][c]. One thread
// per column, `chunk_rows` rows per grid row; i8 rows accumulate exactly in
// signed int64 limbs (chunk_rows <= 2^24), i32 rows through the partially
// folded M31 accumulator. Blocks: col_tiles x n_chunks, flattened.
TC_GLOBAL tc_combine_rows(const void *mat, uint32_t is_i8, uint64_t R, uint64_t C, uint32_t G, const uint32_t *coeffs, uint64_t chunk_rows, uint32_t col_tiles, uint32_t *partials) {
    TC_THREADS
        const uint32_t tile = TC_BLOCK_ID % col_tiles;
        const uint64_t chunk = TC_BLOCK_ID / col_tiles;
        const uint64_t c = (uint64_t)tile * TC_BLOCK_DIM + tid;
        if (c < C) {
            const uint64_t r0 = chunk * chunk_rows;
            const uint64_t r1 = r0 + chunk_rows < R ? r0 + chunk_rows : R;
            for (uint32_t g = 0; g < G; ++g) {
                qm out;
                if (is_i8) {
                    const int8_t *m = (const int8_t *)mat;
                    iacc s = iacc_zero();
                    for (uint64_t i = r0; i < r1; ++i) iacc_mac(s, m[i * C + c], qm_load(coeffs, (uint64_t)g * R + i));
                    out = iacc_get(s);
                } else {
                    const int32_t *m = (const int32_t *)mat;
                    pacc s = pacc_zero();
                    for (uint64_t i = r0; i < r1; ++i) pacc_mac(s, m31_from_i32(m[i * C + c]), qm_load(coeffs, (uint64_t)g * R + i));
                    out = pacc_get(s);
                }
                qm_store(partials, (chunk * G + g) * C + c, out);
            }
        }
    TC_END_THREADS
}

// out[j] = sum_chunk partials[chunk][j], j < n (= G * C).
TC_GLOBAL tc_sum_chunks(const uint32_t *partials, uint64_t n, uint64_t n_chunks, uint32_t *out) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t j = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; j < n; j += stride) {
            qacc s = qacc_zero();
            for (uint64_t ch = 0; ch < n_chunks; ++ch) qacc_add(s, qm_load(partials, ch * n + j));
            qm_store(out, j, qacc_get(s));
        }
    TC_END_THREADS
}

// out[k] = sum_n m[k][n] vec[n]: one block per row, exact int64 limb sums
// for C <= 2^24 (all C products end up in one int64 per limb: C * 2^7 * 2^31
// < 2^63; the host checks it), integer tree in shared memory.
TC_GLOBAL tc_row_dots_i8(const int8_t *m, uint64_t C, const uint32_t *vec, uint32_t *out) {
    TC_SHARED int64_t sh[4 * TC_TB];
    const uint64_t k = TC_BLOCK_ID;
    TC_THREADS
        iacc s = iacc_zero();
        for (uint64_t n = tid; n < C; n += TC_BLOCK_DIM) iacc_mac(s, m[k * C + n], qm_load(vec, n));
        for (int l = 0; l < 4; ++l) sh[4 * tid + l] = s.v[l];
    TC_END_THREADS
    TC_SYNC();
    for (uint32_t s = TC_BLOCK_DIM >> 1; s > 0; s >>= 1) {
        TC_THREADS
            if (tid < s)
                for (int l = 0; l < 4; ++l) sh[4 * tid + l] += sh[4 * (tid + s) + l];
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        if (tid == 0) {
            iacc s;
            for (int l = 0; l < 4; ++l) s.v[l] = sh[l];
            qm_store(out, k, iacc_get(s));
        }
    TC_END_THREADS
}

// MLE of an int32 vector: sum_hi pre[hi] * (sum_lo v[hi 2^lo_bits + lo] suf[lo]).
// Block b takes hi = b, b + nblocks, ...; the inner sums use the folded M31
// accumulator (4 base products per entry), one QM31 mul per (hi, thread).
// Last-block reduction into `result` as tc_sc_round.
TC_GLOBAL tc_mle_i32(const int32_t *v, uint64_t count, uint32_t lo_bits, const uint32_t *pre, const uint32_t *suf, uint32_t *partials, uint32_t *counter, uint32_t *result) {
    TC_SHARED qm sh[TC_TB];
    TC_SHARED uint32_t last;
    const uint64_t lo_n = 1ull << lo_bits;
    const uint64_t hi_n = count >> lo_bits;
    TC_THREADS
        qacc outer = qacc_zero();
        for (uint64_t hi = TC_BLOCK_ID; hi < hi_n; hi += TC_NBLOCKS) {
            pacc in = pacc_zero();
            bool any = false;
            for (uint64_t lo = tid; lo < lo_n; lo += TC_BLOCK_DIM) {
                pacc_mac(in, m31_from_i32(v[hi * lo_n + lo]), qm_load(suf, lo));
                any = true;
            }
            if (any) qacc_add(outer, qm_mul(qm_load(pre, hi), pacc_get(in)));
        }
        sh[tid] = qacc_get(outer);
    TC_END_THREADS
    TC_SYNC();
    for (uint32_t s = TC_BLOCK_DIM >> 1; s > 0; s >>= 1) {
        TC_THREADS
            if (tid < s) sh[tid] = qm_add(sh[tid], sh[tid + s]);
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        if (tid == 0) {
            qm_store(partials, TC_BLOCK_ID, sh[0]);
            TC_FENCE();
            last = (TC_ATOMIC_INC(counter) == TC_NBLOCKS - 1) ? 1u : 0u;
        }
    TC_END_THREADS
    TC_SYNC();
    TC_THREADS
        if (tid == 0 && last) {
            qacc s = qacc_zero();
            const volatile uint32_t *vp = partials;
            for (uint32_t b = 0; b < TC_NBLOCKS; ++b) qacc_add(s, qm{vp[4 * b], vp[4 * b + 1], vp[4 * b + 2], vp[4 * b + 3]});
            qm_store(result, 0, qacc_get(s));
            *counter = 0;
        }
    TC_END_THREADS
}

// ===========================================================================
// Integer matmul accumulators acc[t][n] = sum_k X[t][k] W[k][n] (int64, exact
// for K < 2^24 with |x| < 2^31). 64 x 64 output tiles, 256 threads x (4 x 4),
// K step 32 through shared memory. Blocks: tiles_n x tiles_t, flattened.
// (Production: when X fits int8, the dp4a / IMMA tensor-core path; see
// cuda.md. This is the exact integer reference kernel.)
// ===========================================================================

static constexpr uint32_t MM_B = 64, MM_K = 32;

TC_GLOBAL tc_matmul_i32_i8(const int32_t *x, const int8_t *w, uint32_t T, uint32_t K, uint32_t N, uint32_t tiles_n, int64_t *out) {
    TC_SHARED int32_t xs[MM_B * MM_K];
    TC_SHARED int32_t ws[MM_K * MM_B];
    TC_PRIV(int64_t, acc, 16);
    const uint32_t bn = TC_BLOCK_ID % tiles_n, bt = TC_BLOCK_ID / tiles_n;
    TC_THREADS
        for (int q = 0; q < 16; ++q) TC_P(acc)[q] = 0;
    TC_END_THREADS
    for (uint32_t k0 = 0; k0 < K; k0 += MM_K) {
        TC_THREADS
            for (uint32_t e = tid; e < MM_B * MM_K; e += TC_BLOCK_DIM) {
                const uint32_t rt = e / MM_K, kk = e % MM_K;
                const uint32_t gt = bt * MM_B + rt, gk = k0 + kk;
                xs[e] = (gt < T && gk < K) ? x[(uint64_t)gt * K + gk] : 0;
                const uint32_t wk = e / MM_B, wn = e % MM_B;
                const uint32_t gk2 = k0 + wk, gn = bn * MM_B + wn;
                ws[e] = (gk2 < K && gn < N) ? w[(uint64_t)gk2 * N + gn] : 0;
            }
        TC_END_THREADS
        TC_SYNC();
        TC_THREADS
            const uint32_t ty = tid / 16, tx = tid % 16;
            for (uint32_t kk = 0; kk < MM_K; ++kk)
                for (int a = 0; a < 4; ++a) {
                    const int64_t xv = xs[(ty * 4 + a) * MM_K + kk];
                    for (int b = 0; b < 4; ++b) TC_P(acc)[a * 4 + b] += xv * ws[kk * MM_B + tx * 4 + b];
                }
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        const uint32_t ty = tid / 16, tx = tid % 16;
        for (int a = 0; a < 4; ++a)
            for (int b = 0; b < 4; ++b) {
                const uint32_t gt = bt * MM_B + ty * 4 + a, gn = bn * MM_B + tx * 4 + b;
                if (gt < T && gn < N) out[(uint64_t)gt * N + gn] = TC_P(acc)[a * 4 + b];
            }
    TC_END_THREADS
}

// int8 x int8 path (activations that fit int8): the same 64 x 64 tiles, K
// packed 4 per u32 in shared memory (xs[row][kq], ws[kq][col], k = 4 kq + byte)
// and one dp4a per 4 products. int32 accumulators are exact for K < 2^17
// (|x w| <= 2^14; the host declines larger K to the int64 kernel). X crosses
// PCIe as 1 B per entry instead of 4.
static constexpr uint32_t MM_KQ = MM_K / 4;

TC_DEV uint32_t mm_pack4(const int8_t *p, uint64_t stride, uint32_t avail) {
    uint32_t v = 0;
    for (uint32_t b = 0; b < 4; ++b)
        if (b < avail) v |= (uint32_t)(uint8_t)p[b * stride] << (8 * b);
    return v;
}

TC_GLOBAL tc_matmul_i8_dp4a(const int8_t *x, const int8_t *w, uint32_t T, uint32_t K, uint32_t N, uint32_t tiles_n, int64_t *out) {
    TC_SHARED uint32_t xs[MM_B * MM_KQ];
    TC_SHARED uint32_t ws[MM_KQ * MM_B];
    TC_PRIV(int32_t, acc, 16);
    const uint32_t bn = TC_BLOCK_ID % tiles_n, bt = TC_BLOCK_ID / tiles_n;
    TC_THREADS
        for (int q = 0; q < 16; ++q) TC_P(acc)[q] = 0;
    TC_END_THREADS
    for (uint32_t k0 = 0; k0 < K; k0 += MM_K) {
        TC_THREADS
            for (uint32_t e = tid; e < MM_B * MM_KQ; e += TC_BLOCK_DIM) {
                const uint32_t rt = e / MM_KQ, kq = e % MM_KQ;
                const uint32_t gt = bt * MM_B + rt, gk = k0 + 4 * kq;
                xs[e] = (gt < T && gk < K) ? mm_pack4(x + (uint64_t)gt * K + gk, 1, K - gk) : 0u;
                const uint32_t wq = e / MM_B, wn = e % MM_B;
                const uint32_t gk2 = k0 + 4 * wq, gn = bn * MM_B + wn;
                ws[e] = (gk2 < K && gn < N) ? mm_pack4(w + (uint64_t)gk2 * N + gn, N, K - gk2) : 0u;
            }
        TC_END_THREADS
        TC_SYNC();
        TC_THREADS
            const uint32_t ty = tid / 16, tx = tid % 16;
            for (uint32_t kq = 0; kq < MM_KQ; ++kq)
                for (int a = 0; a < 4; ++a) {
                    const uint32_t xv = xs[(ty * 4 + a) * MM_KQ + kq];
                    for (int b = 0; b < 4; ++b) TC_P(acc)[a * 4 + b] = TC_DP4A(xv, ws[kq * MM_B + tx * 4 + b], TC_P(acc)[a * 4 + b]);
                }
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        const uint32_t ty = tid / 16, tx = tid % 16;
        for (int a = 0; a < 4; ++a)
            for (int b = 0; b < 4; ++b) {
                const uint32_t gt = bt * MM_B + ty * 4 + a, gn = bn * MM_B + tx * 4 + b;
                if (gt < T && gn < N) out[(uint64_t)gt * N + gn] = TC_P(acc)[a * 4 + b];
            }
    TC_END_THREADS
}

// ===========================================================================
// Reed-Solomon row encoding: stwo's forward circle FFT of each row (C
// coefficients zero-padded to E = 2^log_e), then column-major codeword,
// Blake2s column leaves and Merkle nodes.
//
// Layer i >= 1 (line layers) pairs (idx0, idx0 + 2^i), idx0 = (h << (i+1)) + l,
// twiddle tw[tw_len - 2^(log_e - i) + h]; layer 0 (circle layer) pairs
// (2p, 2p + 1) with x = tw[2q], y = tw[2q + 1], q = p >> 2 and twiddles
// (y, -y, -x, x)[p & 3] (stwo evaluateBufferTailLayers). Butterfly:
// t = v1 tw; (v0, v1) = (v0 + t, v0 - t). On a zero-padded row the layers
// i >= log_c only copy, so tc_rs_expand writes E / C copies of the row and
// the layers log_c - 1 .. 0 run: global layers above the tile, then one
// shared-memory kernel for the rest (tile 2^11 words).
// ===========================================================================

static constexpr uint32_t RS_TILE_LOG = 11;

TC_GLOBAL tc_rs_expand(const void *mat, uint32_t is_i8, uint32_t log_c, uint32_t log_e, uint64_t rows, uint64_t row0, uint32_t *scratch) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        const uint64_t n = rows << log_e;
        const uint64_t cmask = (1ull << log_c) - 1;
        for (uint64_t e = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; e < n; e += stride) {
            const uint64_t r = e >> log_e;
            const uint64_t src = ((row0 + r) << log_c) + (e & cmask);
            scratch[e] = is_i8 ? m31_from_i32(((const int8_t *)mat)[src]) : m31_from_i32(((const int32_t *)mat)[src]);
        }
    TC_END_THREADS
}

TC_DEV void rs_butterfly(uint32_t &v0, uint32_t &v1, uint32_t t) {
    const uint32_t m = m31_mul(v1, t);
    v1 = m31_sub(v0, m);
    v0 = m31_add(v0, m);
}

TC_DEV uint32_t rs_circle_twiddle(const uint32_t *tw, uint64_t p) {
    const uint64_t q = p >> 2;
    switch (p & 3) {
        case 0: return tw[2 * q + 1];
        case 1: return m31_neg(tw[2 * q + 1]);
        case 2: return m31_neg(tw[2 * q]);
        default: return tw[2 * q];
    }
}

// One line layer i (>= tile) over all rows: rows * E / 2 butterflies.
TC_GLOBAL tc_rs_layer(uint32_t *scratch, uint64_t rows, uint32_t log_e, uint32_t i, const uint32_t *tw, uint32_t tw_len) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        const uint64_t half_e = 1ull << (log_e - 1);
        const uint64_t n = rows * half_e;
        const uint32_t off = tw_len - (1u << (log_e - i));
        for (uint64_t p = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; p < n; p += stride) {
            const uint64_t r = p >> (log_e - 1), q = p & (half_e - 1);
            const uint64_t h = q >> i, l = q & ((1ull << i) - 1);
            uint32_t *row = scratch + (r << log_e);
            const uint64_t i0 = (h << (i + 1)) + l;
            rs_butterfly(row[i0], row[i0 + (1ull << i)], tw[off + h]);
        }
    TC_END_THREADS
}

// Layers top .. 1 and the circle layer 0 of one 2^tile_log tile per block
// (blocks: rows * E / tile, flattened), in shared memory.
TC_GLOBAL tc_rs_tail(uint32_t *scratch, uint32_t log_e, uint32_t tile_log, uint32_t top, const uint32_t *tw, uint32_t tw_len) {
    TC_SHARED uint32_t sh[1u << RS_TILE_LOG];
    const uint64_t tile = 1ull << tile_log;
    const uint64_t tiles_per_row = 1ull << (log_e - tile_log);
    const uint64_t r = TC_BLOCK_ID / tiles_per_row, ti = TC_BLOCK_ID % tiles_per_row;
    uint32_t *row = scratch + (r << log_e);
    const uint64_t base = ti * tile;
    TC_THREADS
        for (uint64_t e = tid; e < tile; e += TC_BLOCK_DIM) sh[e] = row[base + e];
    TC_END_THREADS
    TC_SYNC();
    for (int32_t i = (int32_t)top; i >= 0; --i) {
        TC_THREADS
            for (uint64_t lp = tid; lp < tile / 2; lp += TC_BLOCK_DIM) {
                if (i > 0) {
                    const uint64_t lh = lp >> i, ll = lp & ((1ull << i) - 1);
                    const uint64_t i0 = (lh << (i + 1)) + ll;
                    const uint64_t h = (base + i0) >> (i + 1);
                    rs_butterfly(sh[i0], sh[i0 + (1ull << i)], tw[tw_len - (1u << (log_e - i)) + h]);
                } else {
                    rs_butterfly(sh[2 * lp], sh[2 * lp + 1], rs_circle_twiddle(tw, base / 2 + lp));
                }
            }
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        for (uint64_t e = tid; e < tile; e += TC_BLOCK_DIM) row[base + e] = sh[e];
    TC_END_THREADS
}

// Column leaves for rows [row0, row0 + rows) of R_total: copies the chunk
// into the column-major codeword enc[j * R_total + r] and absorbs it into
// column j's Blake2s state (8 words per column in `states`); chunks hold a
// multiple of 16 rows except the last, so a block never spans chunks. The
// last chunk writes the digests to nodes[E + j] (8 words each).
TC_GLOBAL tc_rs_leaves(const uint32_t *scratch, uint32_t log_e, uint64_t rows, uint64_t row0, uint64_t R_total, uint32_t last_chunk, uint32_t *states, uint32_t *enc, uint32_t *nodes) {
    TC_THREADS
        const uint64_t E = 1ull << log_e;
        const uint64_t j = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid;
        if (j < E) {
            uint32_t h[8], m[16];
            if (row0 == 0) b2s_init(h);
            else for (int k = 0; k < 8; ++k) h[k] = states[8 * j + k];
            for (uint64_t r = 0; r < rows; ++r) {
                const uint64_t gr = row0 + r;
                const uint32_t w = scratch[(r << log_e) + j];
                enc[j * R_total + gr] = w;
                m[gr & 15] = w;
                if ((gr & 15) == 15) b2s_compress(h, m, (gr + 1) * 4, gr + 1 == R_total);
            }
            if (last_chunk) {
                if (R_total & 15) {
                    for (uint64_t k = R_total & 15; k < 16; ++k) m[k] = 0;
                    b2s_compress(h, m, R_total * 4, true);
                }
                for (int k = 0; k < 8; ++k) nodes[8 * (E + j) + k] = h[k];
            } else {
                for (int k = 0; k < 8; ++k) states[8 * j + k] = h[k];
            }
        }
    TC_END_THREADS
}

// Merkle parents of one level: nodes[idx] = H(nodes[2 idx] || nodes[2 idx + 1]),
// idx in [level, 2 level).
TC_GLOBAL tc_merkle_level(uint32_t *nodes, uint64_t level) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t k = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; k < level; k += stride) {
            const uint64_t idx = level + k;
            b2s_node(nodes + 16 * idx, nodes + 16 * idx + 8, nodes + 8 * idx);
        }
    TC_END_THREADS
}

// All levels from `level` (<= a few thousand nodes) down to the root in one
// single-block launch, with a block barrier between levels.
TC_GLOBAL tc_merkle_top(uint32_t *nodes, uint64_t level) {
    for (uint64_t lv = level; lv >= 1; lv >>= 1) {
        TC_THREADS
            for (uint64_t k = tid; k < lv; k += TC_BLOCK_DIM) {
                const uint64_t idx = lv + k;
                b2s_node(nodes + 16 * idx, nodes + 16 * idx + 8, nodes + 8 * idx);
            }
        TC_END_THREADS
        TC_SYNC();
    }
}

// ===========================================================================
// LogUp-GKR: one fraction-tree layer for ALL instances in one launch.
// Instance k has n_out[k] output fractions; its inputs (num, den QM31) start
// at in_off[k], its outputs at out_off[k] (prefix sums of n_out; out_off has
// n_inst + 1 entries). Output j of instance k combines the adjacent pair
// (2j, 2j + 1): (n0 d1 + n1 d0, d0 d1). A thread finds its instance by binary
// search over out_off, so a layer is one launch whatever the number and the
// heights of the instances (RV64 PR #314 measured 15-19k GKR launches per
// block from per-instance launches; see cuda.md). Not yet wired into
// accel.gkr_prove: emulation-tested against a CPU reference only.
// ===========================================================================

TC_GLOBAL tc_gkr_layer(const uint64_t *in_off, const uint64_t *out_off, uint32_t n_inst, const uint32_t *num_in, const uint32_t *den_in, uint32_t *num_out, uint32_t *den_out) {
    TC_THREADS
        const uint64_t total = out_off[n_inst];
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t g = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; g < total; g += stride) {
            uint32_t lo = 0, hi = n_inst;  // largest k with out_off[k] <= g
            while (hi - lo > 1) {
                const uint32_t mid = (lo + hi) / 2;
                if (out_off[mid] <= g) lo = mid; else hi = mid;
            }
            const uint64_t j = g - out_off[lo];
            const uint64_t s = in_off[lo] + 2 * j;
            const qm n0 = qm_load(num_in, s), n1 = qm_load(num_in, s + 1);
            const qm d0 = qm_load(den_in, s), d1 = qm_load(den_in, s + 1);
            qm_store(num_out, g, qm_add(qm_mul(n0, d1), qm_mul(n1, d0)));
            qm_store(den_out, g, qm_mul(d0, d1));
        }
    TC_END_THREADS
}


// ===========================================================================
// LogUp-GKR sumcheck rounds for ALL live instances in one launch (wired into
// accel.gkr_prove through tc_gkr_*; the control flow is gkr_prover_fast's).
//
// A job is one instance's current layer: offset `off` in the num/den arenas
// (QM31 elements; every numerator is stored as QM31 so ones and base
// numerators share the secure code path: field arithmetic is exact, so the
// values equal the CPU's typed ones) and length `len` after this launch's
// fold. Flags:
//   GKR_FOLD  fold by r first (in place: v[p] = v[p] + r (v[p + len] - v[p]))
//   GKR_SUM   round sums of the (folded) layer, n_terms = len / 4:
//             e0 = sum_i w_i (n0 + lambda d00 d01), e2 = the same at x = 2,
//             w_i = pre[i >> eq_lo] suf[i & mask] (gkr_prover_fast's eq
//             table factored as prefix (x) suffix, as metal/gkr.zig)
//   GKR_MASK  (without SUM) copy num/den at positions 0, 1 (< len) into the
//             job's 64-B result slot: the layer mask / the output claim.
// Fold and sum are fused: the thread owning term i owns positions 2i, 2i+1,
// len/2 + 2i, len/2 + 2i + 1 of the folded layer, and only it reads their
// pre-fold sources p and p + len, so the in-place fold is race-free. Blocks
// are assigned to jobs by `block_start` (prefix sums, n_jobs + 1 entries);
// block partials (2 QM31) are reduced per job by the last block (ticket
// counter) straight into `result` (the host-mapped mailbox): one launch, one
// sync and 32 B per instance per round.
// ===========================================================================

static constexpr uint32_t GKR_FOLD = 1, GKR_SUM = 2, GKR_MASK = 4;

struct GkrJob {
    uint64_t off;
    uint64_t len;
    uint32_t flags;
    uint32_t _pad;
};

TC_DEV qm gkr_fetch(uint32_t *v, uint64_t p, uint64_t len, bool fold, qm r) {
    const qm lo = qm_load(v, p);
    if (!fold) return lo;
    const qm out = qm_add(qm_mul(r, qm_sub(qm_load(v, p + len), lo)), lo);
    qm_store(v, p, out);
    return out;
}

TC_GLOBAL tc_gkr_round(const GkrJob *jobs, uint32_t n_jobs, const uint32_t *block_start, uint32_t *num, uint32_t *den, const uint32_t *pre, const uint32_t *suf, uint32_t eq_lo, qm lambda, qm r, uint32_t *partials, uint32_t *counter, uint32_t *result) {
    TC_SHARED qm sh[2 * TC_TB];
    TC_SHARED uint32_t last;
    uint32_t lo_j = 0, hi_j = n_jobs;  // largest job with block_start <= block id
    while (hi_j - lo_j > 1) {
        const uint32_t mid = (lo_j + hi_j) / 2;
        if (block_start[mid] <= TC_BLOCK_ID) lo_j = mid; else hi_j = mid;
    }
    const GkrJob job = jobs[lo_j];
    const uint32_t jb = TC_BLOCK_ID - block_start[lo_j];
    const uint32_t nb = block_start[lo_j + 1] - block_start[lo_j];
    const bool fold = (job.flags & GKR_FOLD) != 0;
    uint32_t *nm = num + 4 * job.off;
    uint32_t *dn = den + 4 * job.off;
    const uint64_t L = job.len;
    TC_THREADS
        qacc a0 = qacc_zero(), a2 = qacc_zero();
        const uint64_t stride = (uint64_t)nb * TC_BLOCK_DIM;
        if (job.flags & GKR_SUM) {
            const uint64_t n_terms = L / 4;
            const uint64_t emask = (1ull << eq_lo) - 1;
            for (uint64_t i = (uint64_t)jb * TC_BLOCK_DIM + tid; i < n_terms; i += stride) {
                const uint64_t lo = 2 * i, hi = 2 * (n_terms + i);
                const qm d00 = gkr_fetch(dn, lo, L, fold, r), d01 = gkr_fetch(dn, lo + 1, L, fold, r);
                const qm d10 = gkr_fetch(dn, hi, L, fold, r), d11 = gkr_fetch(dn, hi + 1, L, fold, r);
                const qm n00 = gkr_fetch(nm, lo, L, fold, r), n01 = gkr_fetch(nm, lo + 1, L, fold, r);
                const qm n10 = gkr_fetch(nm, hi, L, fold, r), n11 = gkr_fetch(nm, hi + 1, L, fold, r);
                const qm d20 = qm_sub(qm_add(d10, d10), d00), d21 = qm_sub(qm_add(d11, d11), d01);
                const qm n20 = qm_sub(qm_add(n10, n10), n00), n21 = qm_sub(qm_add(n11, n11), n01);
                const qm n0 = qm_add(qm_mul(n00, d01), qm_mul(d00, n01));
                const qm n2 = qm_add(qm_mul(n20, d21), qm_mul(d20, n21));
                const qm w = qm_mul(qm_load(pre, i >> eq_lo), qm_load(suf, i & emask));
                qacc_add(a0, qm_mul(w, qm_add(n0, qm_mul(lambda, qm_mul(d00, d01)))));
                qacc_add(a2, qm_mul(w, qm_add(n2, qm_mul(lambda, qm_mul(d20, d21)))));
            }
        } else {
            for (uint64_t p = (uint64_t)jb * TC_BLOCK_DIM + tid; p < L; p += stride) {
                const qm vn = gkr_fetch(nm, p, L, fold, r), vd = gkr_fetch(dn, p, L, fold, r);
                if ((job.flags & GKR_MASK) && p < 2) {
                    qm_store(result, 4ull * lo_j + p, vn);
                    qm_store(result, 4ull * lo_j + 2 + p, vd);
                }
            }
        }
        sh[2 * tid] = qacc_get(a0);
        sh[2 * tid + 1] = qacc_get(a2);
    TC_END_THREADS
    TC_SYNC();
    for (uint32_t s = TC_BLOCK_DIM >> 1; s > 0; s >>= 1) {
        TC_THREADS
            if (tid < s)
                for (uint32_t k = 0; k < 2; ++k) sh[2 * tid + k] = qm_add(sh[2 * tid + k], sh[2 * (tid + s) + k]);
        TC_END_THREADS
        TC_SYNC();
    }
    TC_THREADS
        if (tid == 0) {
            for (uint32_t k = 0; k < 2; ++k) qm_store(partials, 2ull * TC_BLOCK_ID + k, sh[k]);
            TC_FENCE();
            last = (TC_ATOMIC_INC(counter) == TC_NBLOCKS - 1) ? 1u : 0u;
        }
    TC_END_THREADS
    TC_SYNC();
    TC_THREADS
        if (tid == 0 && last) {
            const volatile uint32_t *vp = partials;
            for (uint32_t j = 0; j < n_jobs; ++j) {
                if (!(jobs[j].flags & GKR_SUM)) continue;
                qacc s[2] = {qacc_zero(), qacc_zero()};
                for (uint32_t b = block_start[j]; b < block_start[j + 1]; ++b)
                    for (uint32_t k = 0; k < 2; ++k) {
                        const uint64_t o = 4ull * (2 * b + k);
                        qacc_add(s[k], qm{vp[o], vp[o + 1], vp[o + 2], vp[o + 3]});
                    }
                for (uint32_t k = 0; k < 2; ++k) qm_store(result, 4ull * j + k, qacc_get(s[k]));
            }
            *counter = 0;
        }
    TC_END_THREADS
}

// Top layers of many instances: numerators of `ones` (kind 0) and base
// (kind 1, canonical u32 in `staging`) instances embedded as QM31 into the
// arena; secure numerators and all denominators are copied directly. One
// launch; thread g finds its instance by binary search over `prefix`.
struct GkrTop {
    uint64_t arena_off;
    uint64_t staging_off;
    uint32_t kind;
    uint32_t _pad;
};

TC_GLOBAL tc_gkr_top(const GkrTop *tops, const uint64_t *prefix, uint32_t n, const uint32_t *staging, uint32_t *num) {
    TC_THREADS
        const uint64_t total = prefix[n];
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t g = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; g < total; g += stride) {
            uint32_t lo = 0, hi = n;
            while (hi - lo > 1) {
                const uint32_t mid = (lo + hi) / 2;
                if (prefix[mid] <= g) lo = mid; else hi = mid;
            }
            const uint64_t j = g - prefix[lo];
            const GkrTop tp = tops[lo];
            qm_store(num, tp.arena_off + j, qm{tp.kind == 0 ? 1u : staging[tp.staging_off + j], 0, 0, 0});
        }
    TC_END_THREADS
}

}  // namespace tc
