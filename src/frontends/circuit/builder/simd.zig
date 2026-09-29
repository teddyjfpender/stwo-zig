//! A vector of M31 lanes packed four to a QM31 wire.
//!
//! Port of `crates/circuits/src/simd.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). `[a, b, c, d, e, f]` is the
//! two wires `a + b·i + c·u + d·iu` and `e + f·i`. The unused coordinates of
//! the last wire are unconstrained (for example `one` sets them to 1), which
//! is why `eq` masks them.
//!
//! Every operation follows upstream's `eval!` order (see `ops.zig`). A
//! returned `Simd` borrows wire slices from `ctx.scratch()`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");
const wrappers = @import("wrappers.zig");

const Allocator = std.mem.Allocator;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Var = context_mod.Var;
const Error = context_mod.Error;
const M31Wrapper = wrappers.M31Wrapper;

/// `EXTENSION_DEGREE`: M31 lanes per QM31 wire.
pub const extension_degree = 4;

const unit_vecs = [4]QM31{
    QM31.fromU32Unchecked(1, 0, 0, 0),
    QM31.fromU32Unchecked(0, 1, 0, 0),
    QM31.fromU32Unchecked(0, 0, 1, 0),
    QM31.fromU32Unchecked(0, 0, 0, 1),
};

/// `UNIT_VECS_INV`: the inverses of `i`, `u` and `iu`.
fn unitVecInv(coord: usize) QM31 {
    return unit_vecs[coord].inv() catch unreachable; // the unit vectors are non-zero
}

pub const Simd = struct {
    /// `ceil(len / 4)` wires.
    data: []const Var,
    /// The number of M31 lanes.
    len: usize,

    /// `Simd::from_packed`; `data` must hold exactly `ceil(len / 4)` wires.
    pub fn fromPacked(data: []const Var, len: usize) Simd {
        std.debug.assert(data.len == nWires(len));
        return .{ .data = data, .len = len };
    }

    pub fn format(self: Simd, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("Simd { data: [");
        for (self.data, 0..) |v, i| {
            if (i != 0) try writer.writeAll(", ");
            try writer.print("{f}", .{v});
        }
        try writer.print("], len: {d} }}", .{self.len});
    }
};

fn nWires(len: usize) usize {
    return std.math.divCeil(usize, len, extension_degree) catch unreachable;
}

fn allocWires(comptime V: type, ctx: *context_mod.Context(V), n: usize) Allocator.Error![]Var {
    return ctx.scratch().alloc(Var, n);
}

/// `Simd::repeat`: `len` copies of the constant `value`.
pub fn repeat(comptime V: type, ctx: *context_mod.Context(V), value: M31, len: usize) Error!Simd {
    const v = try ctx.constant(QM31.fromM31(value, value, value, value));
    const data = try allocWires(V, ctx, nWires(len));
    @memset(data, v);
    return .{ .data = data, .len = len };
}

pub fn zero(comptime V: type, ctx: *context_mod.Context(V), len: usize) Error!Simd {
    return repeat(V, ctx, M31.zero(), len);
}

pub fn one(comptime V: type, ctx: *context_mod.Context(V), len: usize) Error!Simd {
    return repeat(V, ctx, M31.one(), len);
}

/// `Simd::eq`: equal on the first `len` lanes. Full wires get an `eq` gate;
/// a partial last wire is compared through `(a - b) .* mask = 0`.
pub fn eq(comptime V: type, ctx: *context_mod.Context(V), a: Simd, b: Simd) Error!void {
    std.debug.assert(a.len == b.len);
    const n_chunks = a.len / extension_degree;
    const n_rem = a.len % extension_degree;
    for (0..n_chunks) |i| try ctx.eq(a.data[i], b.data[i]);
    if (n_rem > 0) {
        const diff = try ctx.sub(a.data[n_chunks], b.data[n_chunks]);
        const mask = try firstOnes(V, ctx, n_rem);
        const masked = try ctx.pointwiseMul(diff, mask);
        try ctx.eq(masked, ctx.zero());
    }
}

const LaneOp = enum { add, sub, pointwise_mul };

fn lanewise(comptime V: type, ctx: *context_mod.Context(V), comptime op: LaneOp, a: Simd, b: Simd) Error!Simd {
    std.debug.assert(a.len == b.len);
    const data = try allocWires(V, ctx, a.data.len);
    for (data, a.data, b.data) |*out, x, y| out.* = switch (op) {
        .add => try ctx.add(x, y),
        .sub => try ctx.sub(x, y),
        .pointwise_mul => try ctx.pointwiseMul(x, y),
    };
    return .{ .data = data, .len = a.len };
}

/// Lane-wise `a + b` (with the add peephole).
pub fn add(comptime V: type, ctx: *context_mod.Context(V), a: Simd, b: Simd) Error!Simd {
    return lanewise(V, ctx, .add, a, b);
}

/// Lane-wise `a - b`.
pub fn sub(comptime V: type, ctx: *context_mod.Context(V), a: Simd, b: Simd) Error!Simd {
    return lanewise(V, ctx, .sub, a, b);
}

/// Lane-wise `a · b` (a pointwise product per wire).
pub fn mul(comptime V: type, ctx: *context_mod.Context(V), a: Simd, b: Simd) Error!Simd {
    return lanewise(V, ctx, .pointwise_mul, a, b);
}

/// Every lane of `a` times the M31 scalar `b` (with the mul peepholes).
pub fn scalarMul(comptime V: type, ctx: *context_mod.Context(V), a: Simd, b: M31Wrapper(Var)) Error!Simd {
    const data = try allocWires(V, ctx, a.data.len);
    for (data, a.data) |*out, x| out.* = try ctx.mul(x, b.get());
    return .{ .data = data, .len = a.len };
}

/// Guesses one wire per value of `hints`, in order.
fn guessWires(comptime V: type, ctx: *context_mod.Context(V), hints: []const V, len: usize) Error!Simd {
    const data = try allocWires(V, ctx, hints.len);
    for (data, hints) |*out, hint| out.* = try ctx.guess(hint);
    return .{ .data = data, .len = len };
}

/// `guess_inv_or_zero`: an unconstrained hint of `1/x` per lane (0 for 0).
/// The caller must constrain it.
pub fn guessInvOrZero(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error!Simd {
    const hints = try ctx.scratch().alloc(V, a.data.len);
    for (hints, a.data) |*hint, x| hint.* = ivalue.pointwiseInvOrZero(V, ctx.get(x));
    return guessWires(V, ctx, hints, a.len);
}

/// `assert_bits`: `a .* a = a` on the first `len` lanes.
pub fn assertBits(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error!void {
    const square = try mul(V, ctx, a, a);
    try eq(V, ctx, a, square);
}

/// `Simd::inv`: the lane-wise inverse; proves every lane non-zero.
pub fn inv(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error!Simd {
    const res = try guessInvOrZero(V, ctx, a);
    const product = try mul(V, ctx, res, a);
    const ones = try one(V, ctx, a.len);
    // Only the first `len` lanes are constrained.
    try eq(V, ctx, product, ones);
    return res;
}

/// `guess_lsb`: a hint of each lane's least significant bit, constrained to
/// be a bit. The caller must prove it is the LSB.
pub fn guessLsb(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error!Simd {
    const hints = try ctx.scratch().alloc(V, a.data.len);
    for (hints, a.data) |*hint, x| hint.* = ivalue.pointwiseLsb(V, ctx.get(x));
    const out = try guessWires(V, ctx, hints, a.len);
    try assertBits(V, ctx, out);
    return out;
}

/// `select`: `if_zero + selector · (if_one - if_zero)`; `selector` is 0/1 per lane.
pub fn select(comptime V: type, ctx: *context_mod.Context(V), selector: Simd, if_zero: Simd, if_one: Simd) Error!Simd {
    const diff = try sub(V, ctx, if_one, if_zero);
    const scaled = try mul(V, ctx, selector, diff);
    return add(V, ctx, if_zero, scaled);
}

/// `unpack`: one M31 wire per lane.
pub fn unpack(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error![]Var {
    const out = try allocWires(V, ctx, a.len);
    for (out, 0..) |*lane, i| lane.* = try unpackIdx(V, ctx, a, i);
    return out;
}

/// `unpack_idx`: lane `idx` as an M31 wire: `x .* e_c`, then `· e_c^{-1}`
/// unless `c = 0`, where `e_c` is the `c`-th unit vector.
pub fn unpackIdx(comptime V: type, ctx: *context_mod.Context(V), a: Simd, idx: usize) Error!Var {
    const wire = a.data[idx / extension_degree];
    const coord = idx % extension_degree;
    const unit_vec = try ctx.constant(unit_vecs[coord]);
    const x = try ctx.pointwiseMul(wire, unit_vec);
    if (coord == 0) return x;
    const unit_inv = try ctx.constant(unitVecInv(coord));
    return ctx.mul(x, unit_inv);
}

/// `pack`: M31 wires into wires of four lanes, `acc + e_j · v_j`.
pub fn pack(comptime V: type, ctx: *context_mod.Context(V), lanes: []const M31Wrapper(Var)) Error!Simd {
    var basis: [4]Var = undefined;
    for (&basis, unit_vecs) |*v, value| v.* = try ctx.constant(value);
    const data = try allocWires(V, ctx, nWires(lanes.len));
    for (data, 0..) |*out, i| {
        var acc = lanes[4 * i].get();
        for (1..4) |j| {
            if (4 * i + j == lanes.len) break;
            const term = try ctx.mul(basis[j], lanes[4 * i + j].get());
            acc = try ctx.add(acc, term);
        }
        out.* = acc;
    }
    return .fromPacked(data, lanes.len);
}

/// `pow2`: `2^n` per lane, where `bits` is the little-endian decomposition of
/// `n` (1 to 5 bit vectors, `n <= 30`).
pub fn pow2(comptime V: type, ctx: *context_mod.Context(V), bits: []const Simd) Error!Simd {
    var res = try one(V, ctx, bits[0].len);
    var power = try wrappers.constM31(V, ctx, M31.fromCanonical(2));
    for (bits, 0..) |bit, bit_idx| {
        const res_if_one = try scalarMul(V, ctx, res, power);
        res = try select(V, ctx, bit, res, res_if_one);
        // Square to the next power of two, except after the last bit.
        if (bit_idx < bits.len - 1) power = try wrappers.mulM31(V, ctx, power, power);
    }
    return res;
}

/// `combine_bits`: `Σ bits[i] · 2^i` per lane, Horner from the top bit
/// (1 to 30 bit vectors). The inverse of `extractBits`.
pub fn combineBits(comptime V: type, ctx: *context_mod.Context(V), bits: []const Simd) Error!Simd {
    var res = bits[bits.len - 1];
    const two = try wrappers.constM31(V, ctx, M31.fromCanonical(2));
    var i = bits.len - 1;
    while (i > 0) {
        i -= 1;
        res = try scalarMul(V, ctx, res, two);
        res = try add(V, ctx, res, bits[i]);
    }
    return res;
}

/// `mark_partly_used`: marks every wire maybe-unused, for a Simd of which
/// only some lanes are consumed.
pub fn markPartlyUsed(comptime V: type, ctx: *context_mod.Context(V), a: Simd) Error!void {
    for (a.data) |v| try ctx.markAsMaybeUnused(v);
}

/// `first_ones`: the constant with the first `n` coordinates 1 and the rest 0.
fn firstOnes(comptime V: type, ctx: *context_mod.Context(V), n: usize) Error!Var {
    return switch (n) {
        1 => ctx.constant(QM31.fromU32Unchecked(1, 0, 0, 0)),
        2 => ctx.constant(QM31.fromU32Unchecked(1, 1, 0, 0)),
        3 => ctx.constant(QM31.fromU32Unchecked(1, 1, 1, 0)),
        else => unreachable, // `n` is `len % 4` and non-zero
    };
}

test {
    _ = @import("simd_test.zig");
}
