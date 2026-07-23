const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const radix8 = @import("fft_radix8.zig");

const M31 = m31.M31;

pub const SimdContract = struct {
    pub const natural_alignment = @alignOf(M31);
    pub const native_width = m31.PACK_WIDTH;
    pub const scalar_tail_supported = true;
    pub const vector_byte_alignment_required = false;
    pub const caller_scratch_bytes = 0;
    pub const in_place = true;
};

/// Validates the in-place geometry that makes the two butterfly halves
/// disjoint and fully contained in `values`. Packed-width divisibility is not
/// required because the kernel owns fixed-width and scalar tails.
pub fn isValidLayerGeometry(values_len: usize, i: u32, h: usize) bool {
    if (i >= @bitSizeOf(usize) - 1) return false;
    const half_block = @as(usize, 1) << @intCast(i);
    const block_len = std.math.mul(usize, half_block, 2) catch return false;
    const block_start = std.math.mul(usize, h, block_len) catch return false;
    const block_end = std.math.add(usize, block_start, block_len) catch return false;
    return block_end <= values_len;
}

pub fn isValidPairGeometry(values_len: usize, h: usize) bool {
    const block_start = std.math.mul(usize, h, 2) catch return false;
    const block_end = std.math.add(usize, block_start, 2) catch return false;
    return block_end <= values_len;
}

/// Applies one forward FFT layer block with hardware-native packed lanes.
pub inline fn fftLayerLoopForwardM31(
    values: []M31,
    i: u32,
    h: usize,
    twid: M31,
) void {
    std.debug.assert(isValidLayerGeometry(values.len, i, h));
    const half_block: usize = @as(usize, 1) << @intCast(i);
    const block_start = h << @intCast(i + 1);
    var lhs = values.ptr + block_start;
    var rhs = lhs + half_block;
    var remaining = half_block;

    // Hardware-native SIMD path with interleaved pipeline execution.
    // By loading and multiplying multiple pairs before storing results,
    // the CPU's out-of-order execution can pipeline independent multiplies.
    const PW = m31.PACK_WIDTH;
    const twid_packed: m31.PackedM31 = @splat(twid.v);

    // 4-way interleaved: process 4 butterfly pairs simultaneously.
    const PW4 = PW * 4;
    while (remaining >= PW4) : (remaining -= PW4) {
        // Load all 4 pairs.
        const v0a = m31.loadPacked(lhs);
        const v1a = m31.loadPacked(rhs);
        const v0b = m31.loadPacked(lhs + PW);
        const v1b = m31.loadPacked(rhs + PW);
        const v0c = m31.loadPacked(lhs + PW * 2);
        const v1c = m31.loadPacked(rhs + PW * 2);
        const v0d = m31.loadPacked(lhs + PW * 3);
        const v1d = m31.loadPacked(rhs + PW * 3);

        // Issue all 4 multiplications (pipeline-friendly: independent operations).
        const ma = m31.mulPacked(v1a, twid_packed);
        const mb = m31.mulPacked(v1b, twid_packed);
        const mc = m31.mulPacked(v1c, twid_packed);
        const md = m31.mulPacked(v1d, twid_packed);

        // Store results (by now the multiplies have completed).
        m31.storePacked(lhs, m31.addPacked(v0a, ma));
        m31.storePacked(rhs, m31.subPacked(v0a, ma));
        m31.storePacked(lhs + PW, m31.addPacked(v0b, mb));
        m31.storePacked(rhs + PW, m31.subPacked(v0b, mb));
        m31.storePacked(lhs + PW * 2, m31.addPacked(v0c, mc));
        m31.storePacked(rhs + PW * 2, m31.subPacked(v0c, mc));
        m31.storePacked(lhs + PW * 3, m31.addPacked(v0d, md));
        m31.storePacked(rhs + PW * 3, m31.subPacked(v0d, md));

        lhs += PW4;
        rhs += PW4;
    }
    // 2-way interleaved fallback for remaining >= 2 packed widths.
    const PW2 = PW * 2;
    while (remaining >= PW2) : (remaining -= PW2) {
        const v0a = m31.loadPacked(lhs);
        const v1a = m31.loadPacked(rhs);
        const v0b = m31.loadPacked(lhs + PW);
        const v1b = m31.loadPacked(rhs + PW);

        const ma = m31.mulPacked(v1a, twid_packed);
        const mb = m31.mulPacked(v1b, twid_packed);

        m31.storePacked(lhs, m31.addPacked(v0a, ma));
        m31.storePacked(rhs, m31.subPacked(v0a, ma));
        m31.storePacked(lhs + PW, m31.addPacked(v0b, mb));
        m31.storePacked(rhs + PW, m31.subPacked(v0b, mb));

        lhs += PW2;
        rhs += PW2;
    }
    // Single packed-width fallback.
    while (remaining >= PW) : (remaining -= PW) {
        m31.butterflyPacked(lhs, rhs, twid_packed);
        lhs += PW;
        rhs += PW;
    }
    // 4-lane SIMD for remainder.
    const VW = m31.VEC_WIDTH;
    const twid_vec: m31.Vec4u32 = @splat(twid.v);
    while (remaining >= VW) : (remaining -= VW) {
        m31.butterflyVec4(lhs, rhs, twid_vec);
        lhs += VW;
        rhs += VW;
    }
    // Scalar tail.
    while (remaining != 0) : (remaining -= 1) {
        const v0 = lhs[0];
        const v1 = rhs[0];
        const mul = v1.mul(twid);
        lhs[0] = v0.add(mul);
        rhs[0] = v0.sub(mul);
        lhs += 1;
        rhs += 1;
    }
}

pub const canFuseThreeLayersPacked = radix8.canFuseThreeLayersPacked;
pub const fftThreeLayersForwardPackedM31 = radix8.forward;
pub const fftThreeLayersForwardPackedM31Batch = radix8.forwardBatch;
pub const fftThreeLayersForwardPackedM31FromDuplicatedHalf = radix8.forwardFromDuplicatedHalf;
pub const fftThreeLayersForwardPackedM31BatchFromDuplicatedHalf = radix8.forwardBatchFromDuplicatedHalf;
pub const fftThreeLayersInversePackedM31 = radix8.inverse;
pub const fftThreeLayersInversePackedM31Normalized = radix8.inverseNormalized;

/// Fused forward pass over the three smallest-block layers (half-block 4, 2,
/// and the adjacent-pair circle layer). All three operate strictly within
/// 8-element blocks, so each block is loaded once, transformed in registers,
/// and stored once. Butterfly order, twiddle selection, and arithmetic are
/// identical to running `fftLayerLoopForwardM31` for half-block 4 and 2
/// followed by the per-pair tail (twiddle pattern `[y, -y, -x, x]`), so the
/// output is bit-identical to the unfused cascade.
///
/// `t2s` is the half-block-4 layer's twiddle slice (one per block).
/// `t01s` is the shared final slice: `t01s[2b] = x_b`, `t01s[2b + 1] = y_b`;
/// the half-block-2 layer reads them as consecutive block twiddles and the
/// pair layer as its `[y, -y, -x, x]` pattern.
pub fn fftBottomThreeLayersForwardM31(
    values: []M31,
    t2s: []const M31,
    t01s: []const M31,
) void {
    std.debug.assert(values.len % 8 == 0);
    const n_blocks = values.len / 8;
    std.debug.assert(t2s.len >= n_blocks);
    std.debug.assert(t01s.len >= n_blocks * 2);

    var b: usize = 0;
    // Two blocks per iteration: each block's three layers form one serial
    // dependency chain, so interleaving two independent chains keeps the
    // vector pipes fed.
    while (b + 2 <= n_blocks) : (b += 2) {
        fusedBottomBlockForward(values.ptr + b * 8, t2s[b], t01s[2 * b], t01s[2 * b + 1]);
        fusedBottomBlockForward(values.ptr + (b + 1) * 8, t2s[b + 1], t01s[2 * b + 2], t01s[2 * b + 3]);
    }
    while (b < n_blocks) : (b += 1) {
        fusedBottomBlockForward(values.ptr + b * 8, t2s[b], t01s[2 * b], t01s[2 * b + 1]);
    }
}

inline fn fusedBottomBlockForward(base: [*]M31, t2_scalar: M31, x: M31, y: M31) void {
    const va = m31.loadVec4(base);
    const vb = m31.loadVec4(base + 4);

    const result = fusedBottomThreeForwardVectors(va, vb, t2_scalar, x, y);
    m31.storeVec4(base, result.lo);
    m31.storeVec4(base + 4, result.hi);
}

const VecPair = struct {
    lo: m31.Vec4u32,
    hi: m31.Vec4u32,
};

inline fn forwardVecButterfly(
    lhs: m31.Vec4u32,
    rhs: m31.Vec4u32,
    twiddle: m31.Vec4u32,
) VecPair {
    const product = m31.mulVec4(rhs, twiddle);
    return .{
        .lo = m31.addVec4(lhs, product),
        .hi = m31.subVec4(lhs, product),
    };
}

inline fn inverseVecButterfly(
    lhs: m31.Vec4u32,
    rhs: m31.Vec4u32,
    twiddle: m31.Vec4u32,
) VecPair {
    return .{
        .lo = m31.addVec4(lhs, rhs),
        .hi = m31.mulVec4(m31.subVec4(lhs, rhs), twiddle),
    };
}

inline fn fusedBottomThreeForwardVectors(
    va: m31.Vec4u32,
    vb: m31.Vec4u32,
    t2_scalar: M31,
    x: M31,
    y: M31,
) VecPair {
    // Layer with half-block 4: one twiddle per block.
    const t2: m31.Vec4u32 = @splat(t2_scalar.v);
    const stage2 = forwardVecButterfly(va, vb, t2);

    // Layer with half-block 2: lhs lanes [a2_0 a2_1 b2_0 b2_1],
    // rhs lanes [a2_2 a2_3 b2_2 b2_3]; twiddles x then y.
    const lo = @shuffle(u32, stage2.lo, stage2.hi, @Vector(4, i32){ 0, 1, -1, -2 });
    const hi = @shuffle(u32, stage2.lo, stage2.hi, @Vector(4, i32){ 2, 3, -3, -4 });
    const tw1 = m31.Vec4u32{ x.v, x.v, y.v, y.v };
    const stage1 = forwardVecButterfly(lo, hi, tw1);

    // Pair layer: evens/odds with twiddle pattern [y, -y, -x, x].
    const e = @shuffle(u32, stage1.lo, stage1.hi, @Vector(4, i32){ 0, -1, 2, -3 });
    const o = @shuffle(u32, stage1.lo, stage1.hi, @Vector(4, i32){ 1, -2, 3, -4 });
    const y_neg = y.neg();
    const x_neg = x.neg();
    const tw0 = m31.Vec4u32{ y.v, y_neg.v, x_neg.v, x.v };
    const stage0 = forwardVecButterfly(e, o, tw0);

    return .{
        .lo = @shuffle(u32, stage0.lo, stage0.hi, @Vector(4, i32){ 0, -1, 1, -2 }),
        .hi = @shuffle(u32, stage0.lo, stage0.hi, @Vector(4, i32){ 2, -3, 3, -4 }),
    };
}

/// Four-layer contiguous tail sharing one load/store per 16-value block.
pub fn fftBottomFourLayersForwardM31(
    values: []M31,
    t3s: []const M31,
    t2s: []const M31,
    t01s: []const M31,
) void {
    std.debug.assert(values.len % 16 == 0);
    const n_blocks = values.len / 16;
    std.debug.assert(t3s.len >= n_blocks);
    std.debug.assert(t2s.len >= n_blocks * 2);
    std.debug.assert(t01s.len >= n_blocks * 4);

    for (0..n_blocks) |block| {
        const base = values.ptr + block * 16;
        const t3: m31.Vec4u32 = @splat(t3s[block].v);
        const stage3a = forwardVecButterfly(m31.loadVec4(base), m31.loadVec4(base + 8), t3);
        const stage3b = forwardVecButterfly(m31.loadVec4(base + 4), m31.loadVec4(base + 12), t3);
        const left = fusedBottomThreeForwardVectors(
            stage3a.lo,
            stage3b.lo,
            t2s[block * 2],
            t01s[block * 4],
            t01s[block * 4 + 1],
        );
        const right = fusedBottomThreeForwardVectors(
            stage3a.hi,
            stage3b.hi,
            t2s[block * 2 + 1],
            t01s[block * 4 + 2],
            t01s[block * 4 + 3],
        );
        m31.storeVec4(base, left.lo);
        m31.storeVec4(base + 4, left.hi);
        m31.storeVec4(base + 8, right.lo);
        m31.storeVec4(base + 12, right.hi);
    }
}

/// Five-layer contiguous tail. This is the largest tail that keeps all 32
/// values in eight architectural SIMD registers on AArch64. It replaces the
/// two separate whole-column passes otherwise left by radix-8 grouping.
pub fn fftBottomFiveLayersForwardM31(
    values: []M31,
    t4s: []const M31,
    t3s: []const M31,
    t2s: []const M31,
    t01s: []const M31,
) void {
    std.debug.assert(values.len % 32 == 0);
    const n_blocks = values.len / 32;
    std.debug.assert(t4s.len >= n_blocks);
    std.debug.assert(t3s.len >= n_blocks * 2);
    std.debug.assert(t2s.len >= n_blocks * 4);
    std.debug.assert(t01s.len >= n_blocks * 8);

    for (0..n_blocks) |block| {
        const base = values.ptr + block * 32;
        const t4: m31.Vec4u32 = @splat(t4s[block].v);
        const s4a = forwardVecButterfly(m31.loadVec4(base), m31.loadVec4(base + 16), t4);
        const s4b = forwardVecButterfly(m31.loadVec4(base + 4), m31.loadVec4(base + 20), t4);
        const s4c = forwardVecButterfly(m31.loadVec4(base + 8), m31.loadVec4(base + 24), t4);
        const s4d = forwardVecButterfly(m31.loadVec4(base + 12), m31.loadVec4(base + 28), t4);

        const t3_left: m31.Vec4u32 = @splat(t3s[block * 2].v);
        const t3_right: m31.Vec4u32 = @splat(t3s[block * 2 + 1].v);
        const s3a = forwardVecButterfly(s4a.lo, s4c.lo, t3_left);
        const s3b = forwardVecButterfly(s4b.lo, s4d.lo, t3_left);
        const s3c = forwardVecButterfly(s4a.hi, s4c.hi, t3_right);
        const s3d = forwardVecButterfly(s4b.hi, s4d.hi, t3_right);

        const groups = [_]VecPair{
            fusedBottomThreeForwardVectors(s3a.lo, s3b.lo, t2s[block * 4], t01s[block * 8], t01s[block * 8 + 1]),
            fusedBottomThreeForwardVectors(s3a.hi, s3b.hi, t2s[block * 4 + 1], t01s[block * 8 + 2], t01s[block * 8 + 3]),
            fusedBottomThreeForwardVectors(s3c.lo, s3d.lo, t2s[block * 4 + 2], t01s[block * 8 + 4], t01s[block * 8 + 5]),
            fusedBottomThreeForwardVectors(s3c.hi, s3d.hi, t2s[block * 4 + 3], t01s[block * 8 + 6], t01s[block * 8 + 7]),
        };
        inline for (groups, 0..) |group, index| {
            m31.storeVec4(base + index * 8, group.lo);
            m31.storeVec4(base + index * 8 + 4, group.hi);
        }
    }
}

/// Applies one adjacent forward butterfly.
pub inline fn fftPairForwardM31(values: []M31, h: usize, twid: M31) void {
    std.debug.assert(isValidPairGeometry(values.len, h));
    const idx0 = h << 1;
    const idx1 = idx0 + 1;
    const v0 = values[idx0];
    const v1 = values[idx1];
    const mul = v1.mul(twid);
    values[idx0] = v0.add(mul);
    values[idx1] = v0.sub(mul);
}

/// Applies one inverse FFT layer block with hardware-native packed lanes.
pub inline fn fftLayerLoopInverseM31(
    values: []M31,
    i: u32,
    h: usize,
    itwid: M31,
) void {
    std.debug.assert(isValidLayerGeometry(values.len, i, h));
    const half_block: usize = @as(usize, 1) << @intCast(i);
    const block_start = h << @intCast(i + 1);
    var lhs = values.ptr + block_start;
    var rhs = lhs + half_block;
    var remaining = half_block;

    // Hardware-native SIMD path with interleaved pipeline execution.
    // By loading and computing multiple pairs before storing results,
    // the CPU's out-of-order execution can pipeline independent multiplies.
    const PW = m31.PACK_WIDTH;
    const itwid_packed: m31.PackedM31 = @splat(itwid.v);

    // 4-way interleaved: process 4 inverse butterfly pairs simultaneously.
    const PW4 = PW * 4;
    while (remaining >= PW4) : (remaining -= PW4) {
        // Load all 4 pairs.
        const v0a = m31.loadPacked(lhs);
        const v1a = m31.loadPacked(rhs);
        const v0b = m31.loadPacked(lhs + PW);
        const v1b = m31.loadPacked(rhs + PW);
        const v0c = m31.loadPacked(lhs + PW * 2);
        const v1c = m31.loadPacked(rhs + PW * 2);
        const v0d = m31.loadPacked(lhs + PW * 3);
        const v1d = m31.loadPacked(rhs + PW * 3);

        // Compute sums and diffs for all 4 pairs.
        const sum_a = m31.addPacked(v0a, v1a);
        const sum_b = m31.addPacked(v0b, v1b);
        const sum_c = m31.addPacked(v0c, v1c);
        const sum_d = m31.addPacked(v0d, v1d);
        const diff_a = m31.subPacked(v0a, v1a);
        const diff_b = m31.subPacked(v0b, v1b);
        const diff_c = m31.subPacked(v0c, v1c);
        const diff_d = m31.subPacked(v0d, v1d);

        // Issue all 4 multiplications (pipeline-friendly: independent operations).
        const ma = m31.mulPacked(diff_a, itwid_packed);
        const mb = m31.mulPacked(diff_b, itwid_packed);
        const mc = m31.mulPacked(diff_c, itwid_packed);
        const md = m31.mulPacked(diff_d, itwid_packed);

        // Store results (by now the multiplies have completed).
        m31.storePacked(lhs, sum_a);
        m31.storePacked(rhs, ma);
        m31.storePacked(lhs + PW, sum_b);
        m31.storePacked(rhs + PW, mb);
        m31.storePacked(lhs + PW * 2, sum_c);
        m31.storePacked(rhs + PW * 2, mc);
        m31.storePacked(lhs + PW * 3, sum_d);
        m31.storePacked(rhs + PW * 3, md);

        lhs += PW4;
        rhs += PW4;
    }
    // 2-way interleaved fallback for remaining >= 2 packed widths.
    const PW2 = PW * 2;
    while (remaining >= PW2) : (remaining -= PW2) {
        const v0a = m31.loadPacked(lhs);
        const v1a = m31.loadPacked(rhs);
        const v0b = m31.loadPacked(lhs + PW);
        const v1b = m31.loadPacked(rhs + PW);

        const sum_a = m31.addPacked(v0a, v1a);
        const sum_b = m31.addPacked(v0b, v1b);
        const diff_a = m31.subPacked(v0a, v1a);
        const diff_b = m31.subPacked(v0b, v1b);

        const ma = m31.mulPacked(diff_a, itwid_packed);
        const mb = m31.mulPacked(diff_b, itwid_packed);

        m31.storePacked(lhs, sum_a);
        m31.storePacked(rhs, ma);
        m31.storePacked(lhs + PW, sum_b);
        m31.storePacked(rhs + PW, mb);

        lhs += PW2;
        rhs += PW2;
    }
    // Single packed-width fallback.
    while (remaining >= PW) : (remaining -= PW) {
        m31.ibutterflyPacked(lhs, rhs, itwid_packed);
        lhs += PW;
        rhs += PW;
    }
    // 4-lane SIMD for remainder.
    const VW = m31.VEC_WIDTH;
    const itwid_vec: m31.Vec4u32 = @splat(itwid.v);
    while (remaining >= VW) : (remaining -= VW) {
        m31.ibutterflyVec4(lhs, rhs, itwid_vec);
        lhs += VW;
        rhs += VW;
    }
    // Scalar tail.
    while (remaining != 0) : (remaining -= 1) {
        const v0 = lhs[0];
        const v1 = rhs[0];
        lhs[0] = v0.add(v1);
        rhs[0] = v0.sub(v1).mul(itwid);
        lhs += 1;
        rhs += 1;
    }
}

/// Fused inverse pass over the three smallest-block layers — the mirror of
/// `fftBottomThreeLayersForwardM31`, run at the START of the inverse cascade:
/// the adjacent-pair layer (itwiddle pattern `[y, -y, -x, x]`), then
/// half-block 2 (itwiddles x, y), then half-block 4 (`it2s[b]`). Inverse
/// butterfly: `lhs' = lhs + rhs; rhs' = (lhs - rhs) * itw`. Bit-identical to
/// the unfused cascade.
pub fn fftBottomThreeLayersInverseM31(
    values: []M31,
    it2s: []const M31,
    it01s: []const M31,
) void {
    std.debug.assert(values.len % 8 == 0);
    const n_blocks = values.len / 8;
    std.debug.assert(it2s.len >= n_blocks);
    std.debug.assert(it01s.len >= n_blocks * 2);

    var b: usize = 0;
    while (b < n_blocks) : (b += 1) {
        const base = values.ptr + b * 8;
        const x = it01s[2 * b];
        const y = it01s[2 * b + 1];
        const result = fusedBottomThreeInverseVectors(
            m31.loadVec4(base),
            m31.loadVec4(base + 4),
            it2s[b],
            x,
            y,
        );
        m31.storeVec4(base, result.lo);
        m31.storeVec4(base + 4, result.hi);
    }
}

inline fn fusedBottomThreeInverseVectors(
    va: m31.Vec4u32,
    vb: m31.Vec4u32,
    it2_scalar: M31,
    x: M31,
    y: M31,
) VecPair {
    // Pair layer: evens/odds, itwiddle pattern [y, -y, -x, x].
    const e = @shuffle(u32, va, vb, @Vector(4, i32){ 0, 2, -1, -3 });
    const o = @shuffle(u32, va, vb, @Vector(4, i32){ 1, 3, -2, -4 });
    const y_neg = y.neg();
    const x_neg = x.neg();
    const tw0 = m31.Vec4u32{ y.v, y_neg.v, x_neg.v, x.v };
    const stage0 = inverseVecButterfly(e, o, tw0);

    // Half-block-2 layer: lhs [x0 x1 x4 x5], rhs [x2 x3 x6 x7],
    // itwiddles x then y.
    const lo = @shuffle(u32, stage0.lo, stage0.hi, @Vector(4, i32){ 0, -1, 2, -3 });
    const hi = @shuffle(u32, stage0.lo, stage0.hi, @Vector(4, i32){ 1, -2, 3, -4 });
    const tw1 = m31.Vec4u32{ x.v, x.v, y.v, y.v };
    const stage1 = inverseVecButterfly(lo, hi, tw1);

    // Half-block-4 layer: lhs [x0 x1 x2 x3], rhs [x4 x5 x6 x7].
    const lhs2 = @shuffle(u32, stage1.lo, stage1.hi, @Vector(4, i32){ 0, 1, -1, -2 });
    const rhs2 = @shuffle(u32, stage1.lo, stage1.hi, @Vector(4, i32){ 2, 3, -3, -4 });
    const it2: m31.Vec4u32 = @splat(it2_scalar.v);
    return inverseVecButterfly(lhs2, rhs2, it2);
}

pub fn fftBottomFourLayersInverseM31(
    values: []M31,
    it3s: []const M31,
    it2s: []const M31,
    it01s: []const M31,
) void {
    std.debug.assert(values.len % 16 == 0);
    const n_blocks = values.len / 16;
    std.debug.assert(it3s.len >= n_blocks);
    std.debug.assert(it2s.len >= n_blocks * 2);
    std.debug.assert(it01s.len >= n_blocks * 4);

    for (0..n_blocks) |block| {
        const base = values.ptr + block * 16;
        const left = fusedBottomThreeInverseVectors(
            m31.loadVec4(base),
            m31.loadVec4(base + 4),
            it2s[block * 2],
            it01s[block * 4],
            it01s[block * 4 + 1],
        );
        const right = fusedBottomThreeInverseVectors(
            m31.loadVec4(base + 8),
            m31.loadVec4(base + 12),
            it2s[block * 2 + 1],
            it01s[block * 4 + 2],
            it01s[block * 4 + 3],
        );
        const it3: m31.Vec4u32 = @splat(it3s[block].v);
        const stage3a = inverseVecButterfly(left.lo, right.lo, it3);
        const stage3b = inverseVecButterfly(left.hi, right.hi, it3);
        m31.storeVec4(base, stage3a.lo);
        m31.storeVec4(base + 4, stage3b.lo);
        m31.storeVec4(base + 8, stage3a.hi);
        m31.storeVec4(base + 12, stage3b.hi);
    }
}

pub fn fftBottomFiveLayersInverseM31(
    values: []M31,
    it4s: []const M31,
    it3s: []const M31,
    it2s: []const M31,
    it01s: []const M31,
) void {
    std.debug.assert(values.len % 32 == 0);
    const n_blocks = values.len / 32;
    std.debug.assert(it4s.len >= n_blocks);
    std.debug.assert(it3s.len >= n_blocks * 2);
    std.debug.assert(it2s.len >= n_blocks * 4);
    std.debug.assert(it01s.len >= n_blocks * 8);

    for (0..n_blocks) |block| {
        const base = values.ptr + block * 32;
        const g0 = fusedBottomThreeInverseVectors(m31.loadVec4(base), m31.loadVec4(base + 4), it2s[block * 4], it01s[block * 8], it01s[block * 8 + 1]);
        const g1 = fusedBottomThreeInverseVectors(m31.loadVec4(base + 8), m31.loadVec4(base + 12), it2s[block * 4 + 1], it01s[block * 8 + 2], it01s[block * 8 + 3]);
        const g2 = fusedBottomThreeInverseVectors(m31.loadVec4(base + 16), m31.loadVec4(base + 20), it2s[block * 4 + 2], it01s[block * 8 + 4], it01s[block * 8 + 5]);
        const g3 = fusedBottomThreeInverseVectors(m31.loadVec4(base + 24), m31.loadVec4(base + 28), it2s[block * 4 + 3], it01s[block * 8 + 6], it01s[block * 8 + 7]);

        const it3_left: m31.Vec4u32 = @splat(it3s[block * 2].v);
        const it3_right: m31.Vec4u32 = @splat(it3s[block * 2 + 1].v);
        const s3a = inverseVecButterfly(g0.lo, g1.lo, it3_left);
        const s3b = inverseVecButterfly(g0.hi, g1.hi, it3_left);
        const s3c = inverseVecButterfly(g2.lo, g3.lo, it3_right);
        const s3d = inverseVecButterfly(g2.hi, g3.hi, it3_right);
        const it4: m31.Vec4u32 = @splat(it4s[block].v);
        const s4a = inverseVecButterfly(s3a.lo, s3c.lo, it4);
        const s4b = inverseVecButterfly(s3b.lo, s3d.lo, it4);
        const s4c = inverseVecButterfly(s3a.hi, s3c.hi, it4);
        const s4d = inverseVecButterfly(s3b.hi, s3d.hi, it4);
        m31.storeVec4(base, s4a.lo);
        m31.storeVec4(base + 4, s4b.lo);
        m31.storeVec4(base + 8, s4c.lo);
        m31.storeVec4(base + 12, s4d.lo);
        m31.storeVec4(base + 16, s4a.hi);
        m31.storeVec4(base + 20, s4b.hi);
        m31.storeVec4(base + 24, s4c.hi);
        m31.storeVec4(base + 28, s4d.hi);
    }
}

/// Applies one adjacent inverse butterfly.
pub inline fn fftPairInverseM31(values: []M31, h: usize, itwid: M31) void {
    std.debug.assert(isValidPairGeometry(values.len, h));
    const idx0 = h << 1;
    const idx1 = idx0 + 1;
    const v0 = values[idx0];
    const v1 = values[idx1];
    values[idx0] = v0.add(v1);
    values[idx1] = v0.sub(v1).mul(itwid);
}

test "circle FFT layer kernels match scalar butterfly laws across lane regimes" {
    const allocator = std.testing.allocator;
    const twid = M31.fromCanonical(1_234_567);
    const itwid = M31.fromCanonical(7_654_321);
    const max_values_len = 1 << 11;
    const vector_bytes = m31.PACK_WIDTH * @sizeOf(M31);
    const alignment = comptime std.mem.Alignment.fromByteUnits(@max(@alignOf(M31), vector_bytes));
    const offset: usize = if (m31.PACK_WIDTH > 1) 1 else 0;
    const before_storage = try allocator.alignedAlloc(M31, alignment, max_values_len + offset);
    defer allocator.free(before_storage);
    const forward_storage = try allocator.alignedAlloc(M31, alignment, max_values_len + offset);
    defer allocator.free(forward_storage);
    const inverse_storage = try allocator.alignedAlloc(M31, alignment, max_values_len + offset);
    defer allocator.free(inverse_storage);
    var prng = std.Random.DefaultPrng.init(0x3c6e_f372_fe94_f82b);
    const rng = prng.random();

    try std.testing.expectEqual(@as(usize, 0), SimdContract.caller_scratch_bytes);
    try std.testing.expect(SimdContract.scalar_tail_supported);
    try std.testing.expect(!SimdContract.vector_byte_alignment_required);
    if (m31.PACK_WIDTH > 1) {
        try std.testing.expect(@intFromPtr((before_storage.ptr + offset)) % vector_bytes != 0);
    }

    var log_half_block: u32 = 0;
    while (log_half_block <= 9) : (log_half_block += 1) {
        const half_block = @as(usize, 1) << @intCast(log_half_block);
        const block_start = half_block * 2;
        const values_len = half_block * 4;
        const before = before_storage[offset .. offset + values_len];
        const forward = forward_storage[offset .. offset + values_len];
        const inverse = inverse_storage[offset .. offset + values_len];
        for (before) |*value| value.* = M31.fromCanonical(rng.intRangeLessThan(u32, 0, m31.Modulus));
        @memcpy(forward, before);
        @memcpy(inverse, before);

        fftLayerLoopForwardM31(forward, log_half_block, 1, twid);
        for (0..values_len) |index| {
            const expected = if (index < block_start or index >= block_start + half_block * 2)
                before[index]
            else if (index < block_start + half_block)
                before[index].add(before[index + half_block].mul(twid))
            else
                before[index - half_block].sub(before[index].mul(twid));
            try std.testing.expect(forward[index].eql(expected));
        }

        fftLayerLoopInverseM31(inverse, log_half_block, 1, itwid);
        for (0..values_len) |index| {
            const expected = if (index < block_start or index >= block_start + half_block * 2)
                before[index]
            else if (index < block_start + half_block)
                before[index].add(before[index + half_block])
            else
                before[index - half_block].sub(before[index]).mul(itwid);
            try std.testing.expect(inverse[index].eql(expected));
        }
    }
}

test "packed radix-8 pass matches three independent stages" {
    const log_size: u32 = 10;
    const value_count = @as(usize, 1) << @intCast(log_size);
    const pair_count = value_count / 2;
    var prng = std.Random.DefaultPrng.init(0x510e_527f_ade6_82d1);
    const random = prng.random();

    const input = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(input);
    const expected = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(expected);
    const actual = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(actual);
    const twiddles = try std.testing.allocator.alloc(M31, pair_count);
    defer std.testing.allocator.free(twiddles);

    for (input) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
    for (twiddles) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 1, m31.Modulus));

    const forward_stages = [_]u32{ 9, 5 };
    for (forward_stages) |highest_stage| {
        @memcpy(expected, input);
        @memcpy(actual, input);
        var step: u32 = 0;
        while (step < 3) : (step += 1) {
            const stage = highest_stage - step;
            const count = @as(usize, 1) << @intCast(log_size - stage - 1);
            const offset = pair_count - count * 2;
            for (twiddles[offset .. offset + count], 0..) |twiddle, block| {
                fftLayerLoopForwardM31(expected, stage, block, twiddle);
            }
        }
        fftThreeLayersForwardPackedM31(actual, log_size, highest_stage, twiddles);
        try std.testing.expectEqualSlices(M31, expected, actual);
    }

    // A 2x extension's first active group sees two identical halves. The
    // expansion kernel must synthesize the upper group without reading its
    // deliberately unrelated contents.
    @memcpy(expected, input);
    @memcpy(expected[value_count / 2 ..], expected[0 .. value_count / 2]);
    @memcpy(actual, input);
    fftThreeLayersForwardPackedM31(expected, log_size, 8, twiddles);
    fftThreeLayersForwardPackedM31FromDuplicatedHalf(actual, log_size, 8, twiddles);
    try std.testing.expectEqualSlices(M31, expected, actual);

    const inverse_stages = [_]u32{ 3, 7 };
    for (inverse_stages) |lowest_stage| {
        @memcpy(expected, input);
        @memcpy(actual, input);
        var step: u32 = 0;
        while (step < 3) : (step += 1) {
            const stage = lowest_stage + step;
            const count = @as(usize, 1) << @intCast(log_size - stage - 1);
            const offset = pair_count - count * 2;
            for (twiddles[offset .. offset + count], 0..) |twiddle, block| {
                fftLayerLoopInverseM31(expected, stage, block, twiddle);
            }
        }
        fftThreeLayersInversePackedM31(actual, log_size, lowest_stage, twiddles);
        try std.testing.expectEqualSlices(M31, expected, actual);

        const normalization = M31.fromCanonical(1_234_567);
        for (expected) |*value| value.* = value.mul(normalization);
        @memcpy(actual, input);
        fftThreeLayersInversePackedM31Normalized(
            actual,
            log_size,
            lowest_stage,
            twiddles,
            normalization,
        );
        try std.testing.expectEqualSlices(M31, expected, actual);
    }
}

test "circle FFT geometry rejects out of range and overflow before SIMD access" {
    try std.testing.expect(isValidLayerGeometry(2, 0, 0));
    try std.testing.expect(!isValidLayerGeometry(1, 0, 0));
    try std.testing.expect(!isValidLayerGeometry(8, 2, 1));
    try std.testing.expect(!isValidLayerGeometry(std.math.maxInt(usize), 0, std.math.maxInt(usize)));
    try std.testing.expect(!isValidLayerGeometry(8, @bitSizeOf(usize), 0));

    try std.testing.expect(isValidPairGeometry(4, 1));
    try std.testing.expect(!isValidPairGeometry(3, 1));
    try std.testing.expect(!isValidPairGeometry(std.math.maxInt(usize), std.math.maxInt(usize)));
}

test "circle FFT pair kernels match scalar butterfly laws" {
    const twid = M31.fromCanonical(12_345);
    const itwid = M31.fromCanonical(67_890);
    const before = [_]M31{
        M31.fromCanonical(101),
        M31.fromCanonical(202),
        M31.fromCanonical(303),
        M31.fromCanonical(404),
    };

    var forward = before;
    fftPairForwardM31(&forward, 1, twid);
    try std.testing.expect(forward[0].eql(before[0]));
    try std.testing.expect(forward[1].eql(before[1]));
    try std.testing.expect(forward[2].eql(before[2].add(before[3].mul(twid))));
    try std.testing.expect(forward[3].eql(before[2].sub(before[3].mul(twid))));

    var inverse = before;
    fftPairInverseM31(&inverse, 1, itwid);
    try std.testing.expect(inverse[0].eql(before[0]));
    try std.testing.expect(inverse[1].eql(before[1]));
    try std.testing.expect(inverse[2].eql(before[2].add(before[3])));
    try std.testing.expect(inverse[3].eql(before[2].sub(before[3]).mul(itwid)));
}
