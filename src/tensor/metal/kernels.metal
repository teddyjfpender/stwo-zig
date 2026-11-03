// Tensor-frontend kernels. Compiled after the stwo-zig Metal backend's MSL
// includes (base, m31, extension_fields, blake2s, circle) and its circle
// transform / commitment translation units, whose kernels
// (stwo_zig_circle_rfft_layer, stwo_zig_blake2s_parents_plain_sparse) the
// tensor path dispatches directly.

// ---------------------------------------------------------------------------
// Row encoding (Ligero rows -> circle-FFT RS codewords).
//
// A row holds C = 2^log_c coefficients, zero padded to E = 2^log_e. The top
// log_e - log_c FFT layers of a zero-padded buffer only duplicate the low
// half (the high operand is 0), so after them every C-block of the buffer is
// a copy of the coefficients. `tm_expand_*` writes those copies directly.

struct TmExpandParams {
    uint log_c;
    uint log_e;
    uint rows;   // rows in this chunk
    uint row0;   // first source row of the chunk
};

inline uint tm_from_i32(int x) { return x >= 0 ? uint(x) : uint(x + 0x7fffffff); }

kernel void tm_expand_i32(
    device const int *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant TmExpandParams &p [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint row = gid >> p.log_e;
    if (row >= p.rows) return;
    uint pos = gid & ((1u << p.log_e) - 1u);
    ulong s = (ulong(p.row0 + row) << p.log_c) + (pos & ((1u << p.log_c) - 1u));
    dst[gid] = tm_from_i32(src[s]);
}

kernel void tm_expand_i8(
    device const char *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant TmExpandParams &p [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint row = gid >> p.log_e;
    if (row >= p.rows) return;
    uint pos = gid & ((1u << p.log_e) - 1u);
    ulong s = (ulong(p.row0 + row) << p.log_c) + (pos & ((1u << p.log_c) - 1u));
    dst[gid] = tm_from_i32(int(src[s]));
}

// Low FFT layers (top_layer .. 1) plus the circle layer, fused in threadgroup
// memory over tiles of 2^tile_log values. Layer i butterflies (x, x + 2^i)
// inside aligned 2^(i+1) blocks with twiddle tw[tw_len - 2^(log_e - i) + h],
// h = position >> (i + 1); the circle layer uses circle_twiddle over the first
// line layer (offset tw_len - 2^(log_e - 1)). Same transform as
// stwo's evaluateBufferWithTwiddles.
struct TmTailParams {
    uint log_e;
    uint tile_log;
    uint top_layer;
    uint tw_len;
    uint rows;
};

kernel void tm_rfft_tail(
    device uint *values [[buffer(0)]],
    device const uint *tw [[buffer(1)]],
    constant TmTailParams &p [[buffer(2)]],
    threadgroup uint *tile [[threadgroup(0)]],
    uint gid [[threadgroup_position_in_grid]],
    uint tid [[thread_position_in_threadgroup]],
    uint nthreads [[threads_per_threadgroup]]
) {
    uint tile_size = 1u << p.tile_log;
    uint tiles_per_row = 1u << (p.log_e - p.tile_log);
    uint row = gid / tiles_per_row;
    if (row >= p.rows) return;
    uint p0 = (gid % tiles_per_row) << p.tile_log;
    device uint *src = values + (ulong(row) << p.log_e) + p0;
    for (uint k = tid; k < tile_size; k += nthreads) tile[k] = src[k];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint half_tile = tile_size >> 1u;
    for (uint i = p.top_layer; i >= 1u; --i) {
        uint lo_mask = (1u << i) - 1u;
        uint off = p.tw_len - (1u << (p.log_e - i));
        for (uint k = tid; k < half_tile; k += nthreads) {
            uint idx0 = ((k >> i) << (i + 1u)) | (k & lo_mask);
            uint idx1 = idx0 + (1u << i);
            uint t = tw[off + ((p0 + idx0) >> (i + 1u))];
            uint lhs = tile[idx0];
            uint prod = m31_mul(tile[idx1], t);
            tile[idx0] = m31_add(lhs, prod);
            tile[idx1] = m31_sub(lhs, prod);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    device const uint *first = tw + (p.tw_len - (1u << (p.log_e - 1u)));
    for (uint k = tid; k < half_tile; k += nthreads) {
        uint idx0 = k << 1u;
        uint t = circle_twiddle(first, (p0 >> 1u) + k);
        uint lhs = tile[idx0];
        uint prod = m31_mul(tile[idx0 + 1u], t);
        src[idx0] = m31_add(lhs, prod);
        src[idx0 + 1u] = m31_sub(lhs, prod);
    }
}

// ---------------------------------------------------------------------------
// Column leaves: Blake2s over each encoded column's M31 little-endian words
// (rows 0..R), streamed over row chunks. Chunks other than the last hold a
// multiple of 16 rows, so message blocks never straddle chunks. Also writes
// the column-major copy of the codeword that the opening phase reads.
struct TmLeafParams {
    uint log_e;
    uint rows;        // rows in this chunk
    uint row0;        // first row of the chunk
    uint total_rows;  // R
    uint last_chunk;
};

kernel void tm_leaf_absorb(
    device const uint *values [[buffer(0)]],   // chunk, row-major rows x E
    device uint *states [[buffer(1)]],         // E x 8
    device uint *enc_cm [[buffer(2)]],         // column-major E x R
    device uint *nodes [[buffer(3)]],          // Merkle nodes (8 words each)
    constant TmLeafParams &p [[buffer(4)]],
    uint j [[thread_position_in_grid]]
) {
    uint E = 1u << p.log_e;
    if (j >= E) return;
    uint state[8];
    if (p.row0 == 0u) blake2s_init_hash(state);
    else for (uint i = 0u; i < 8u; ++i) state[i] = states[j * 8u + i];
    uint message[16];
    device uint *col = enc_cm + ulong(j) * p.total_rows + p.row0;
    uint r = 0u;
    while (r < p.rows) {
        uint n = min(16u, p.rows - r);
        for (uint w = 0u; w < n; ++w) {
            uint v = values[(ulong(r + w) << p.log_e) + j];
            message[w] = v;
            col[r + w] = v;
        }
        for (uint w = n; w < 16u; ++w) message[w] = 0u;
        r += n;
        bool last = p.last_chunk != 0u && r == p.rows;
        blake2s_compress(state, message, (p.row0 + r) * 4u, last);
    }
    device uint *dst = p.last_chunk != 0u ? nodes + (ulong(E + j) * 8u) : states + j * 8u;
    for (uint i = 0u; i < 8u; ++i) dst[i] = state[i];
}

// ---------------------------------------------------------------------------
// Sumcheck over QM31 factor vectors (MSB-first folding). Up to 4 factors and
// 4 terms of degree <= 3. Each threadgroup writes partial round sums
// (s(0), s(2), s(3)); the host adds partials (field addition is exact, so the
// reduction order does not change the result).

constant uint TM_MAX_FACTORS = 4u;

struct TmScParams {
    uint half_len;   // half of the current length
    uint active;     // entries >= active are zero
    uint work;       // min(half_len, active)
    uint prev_half;  // fused fold: half of the previous length (0: no fold)
    uint prev_active;
    uint n_factors;
    uint n_terms;
    uint deg;
    uint term_len[4];
    uint term_fac[4][3];
    Qm31Value coeff[4];
    Qm31Value r;     // fold challenge (fused fold) / fold kernel challenge
};

inline Qm31Value tm_load(device const uint *f, ulong i) {
    device const uint4 *v = (device const uint4 *)f;
    uint4 x = v[i];
    return { x.x, x.y, x.z, x.w };
}
inline void tm_store(device uint *f, ulong i, Qm31Value q) {
    device uint4 *v = (device uint4 *)f;
    v[i] = uint4(q.a, q.b, q.c, q.d);
}
inline Qm31Value tm_zero() { return { 0u, 0u, 0u, 0u }; }

inline Qm31Value tm_eval_terms(constant TmScParams &p, thread const Qm31Value *cur) {
    Qm31Value v = tm_zero();
    for (uint t = 0u; t < p.n_terms; ++t) {
        Qm31Value prod = cur[p.term_fac[t][0]];
        for (uint k = 1u; k < p.term_len[t]; ++k) prod = qm_mul(prod, cur[p.term_fac[t][k]]);
        Qm31Value c = p.coeff[t];
        if (!(c.a == 1u && c.b == 0u && c.c == 0u && c.d == 0u)) prod = qm_mul(prod, c);
        v = qm_add(v, prod);
    }
    return v;
}

// Folded value of factor `f` at index y (< prev_work) given the old buffer.
inline Qm31Value tm_folded(device const uint *f, constant TmScParams &p, uint y) {
    Qm31Value lo = tm_load(f, y);
    Qm31Value hi = (y + p.prev_half < p.prev_active) ? tm_load(f, y + p.prev_half) : tm_zero();
    return qm_add(lo, qm_mul(p.r, qm_sub(hi, lo)));
}

kernel void tm_sc_round(
    device uint *f0 [[buffer(0)]],
    device uint *f1 [[buffer(1)]],
    device uint *f2 [[buffer(2)]],
    device uint *f3 [[buffer(3)]],
    device uint *partials [[buffer(4)]],   // per threadgroup: 3 QM31
    constant TmScParams &p [[buffer(5)]],
    threadgroup Qm31Value *scratch [[threadgroup(0)]],
    uint gid [[thread_position_in_grid]],
    uint tg [[threadgroup_position_in_grid]],
    uint tid [[thread_position_in_threadgroup]],
    uint tgsize [[threads_per_threadgroup]],
    uint grid [[threads_per_grid]]
) {
    device uint *fs[4] = { f0, f1, f2, f3 };
    Qm31Value acc0 = tm_zero(), acc2 = tm_zero(), acc3 = tm_zero();
    for (uint x = gid; x < p.work; x += grid) {
        Qm31Value lo[TM_MAX_FACTORS], diff[TM_MAX_FACTORS], cur[TM_MAX_FACTORS];
        bool has_hi = x + p.half_len < p.active;
        for (uint j = 0u; j < p.n_factors; ++j) {
            Qm31Value l, h;
            if (p.prev_half != 0u) {
                // fused: fold the previous round into positions x and x + half
                l = tm_folded(fs[j], p, x);
                h = has_hi ? tm_folded(fs[j], p, x + p.half_len) : tm_zero();
            } else {
                l = tm_load(fs[j], x);
                h = has_hi ? tm_load(fs[j], x + p.half_len) : tm_zero();
            }
            lo[j] = l;
            diff[j] = qm_sub(h, l);
            cur[j] = l;
        }
        if (p.prev_half != 0u) {
            // write back the folded values (other threads never touch x, x + half)
            for (uint j = 0u; j < p.n_factors; ++j) {
                tm_store(fs[j], x, lo[j]);
                if (has_hi) tm_store(fs[j], x + p.half_len, qm_add(lo[j], diff[j]));
            }
        }
        acc0 = qm_add(acc0, tm_eval_terms(p, cur));
        for (uint j = 0u; j < p.n_factors; ++j) cur[j] = qm_add(qm_add(cur[j], diff[j]), diff[j]);
        acc2 = qm_add(acc2, tm_eval_terms(p, cur));
        if (p.deg >= 3u) {
            for (uint j = 0u; j < p.n_factors; ++j) cur[j] = qm_add(cur[j], diff[j]);
            acc3 = qm_add(acc3, tm_eval_terms(p, cur));
        }
    }
    // the folded tail [work, prev_work) beyond x + half also has to be written;
    // it is covered above because prev_work <= 2 * half and x + half < prev_active.
    scratch[tid * 3u] = acc0;
    scratch[tid * 3u + 1u] = acc2;
    scratch[tid * 3u + 2u] = acc3;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint s = tgsize >> 1u; s > 0u; s >>= 1u) {
        if (tid < s) {
            for (uint k = 0u; k < 3u; ++k)
                scratch[tid * 3u + k] = qm_add(scratch[tid * 3u + k], scratch[(tid + s) * 3u + k]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (tid == 0u) {
        for (uint k = 0u; k < 3u; ++k) tm_store(partials, tg * 3u + k, scratch[k]);
    }
}

// Plain fold: f[x] = lo + r (hi - lo) for x < work.
kernel void tm_sc_fold(
    device uint *f0 [[buffer(0)]],
    device uint *f1 [[buffer(1)]],
    device uint *f2 [[buffer(2)]],
    device uint *f3 [[buffer(3)]],
    constant TmScParams &p [[buffer(5)]],
    uint x [[thread_position_in_grid]]
) {
    if (x >= p.work) return;
    device uint *fs[4] = { f0, f1, f2, f3 };
    bool has_hi = x + p.half_len < p.active;
    for (uint j = 0u; j < p.n_factors; ++j) {
        Qm31Value lo = tm_load(fs[j], x);
        Qm31Value hi = has_hi ? tm_load(fs[j], x + p.half_len) : tm_zero();
        tm_store(fs[j], x, qm_add(lo, qm_mul(p.r, qm_sub(hi, lo))));
    }
}
