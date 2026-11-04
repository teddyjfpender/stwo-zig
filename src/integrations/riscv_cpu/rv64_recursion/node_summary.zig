//! M5 node-summary (`NS`) combine gadgets for leaves and k-ary folds (stream
//! canon-vk; binding note rv64-m5-binding.md §2, §3.2(5), §4.1(5)-(6) and
//! review 2 §10.2). These are the in-circuit rules fold v3 applies to its
//! children's public summaries; each gadget takes an EXPLICIT witness so a
//! negative test can mutate one value and see the named constraint fail
//! (corpus W tier, profiles' hook contract `corpus <ID> ...`).
//!
//! Typing rule (binding §2 [R1]): counters, masses, segment indices and depth
//! are integers with explicit bit bounds. Every relation below is an equality
//! between field elements whose integer values stay far below p = 2^31 - 1,
//! so field equality IS integer equality (no wrap). Range checks are Boolean
//! bit decompositions (b*b = b, sum b_i 2^i = v), which `isCircuitValid` sees.
//!
//! Gadgets:
//! - `rangeBits`: v in [0, 2^n), n <= 20.
//! - `leafIndex`: k < MAX_PROOFS, two-sided (k and MAX_PROOFS-1-k in [0,2^16), L05/Z05).
//! - `foldInterval`: per child seg_hi - seg_lo and MAX_PROOFS-1-seg_hi in [0,2^16)
//!   for EVERY child (F6), adjacency seg_lo[i+1] = seg_hi[i] + 1; outputs (first lo, last hi).
//! - `foldMass`: k canonical u32 masses (u16 limbs) summed as integers with the
//!   output proven < p by a guessed complement d = p - 1 - S (review 2 §10.2 gadget, Z04).
//! - `foldDepth`: depth = 1 + max_i depth_i <= D_MAX (F5, Z06).
//! - `foldKappa`: kappa = sum kappa_i, each and the sum in [0, 2^9) (<= MAX_PROOFS = 256).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const B = circuit.builder;
const Q = core.fields.qm31.QM31;
const Var = B.Var;
const Context = B.Context(Q);

pub const MAX_PROOFS: u32 = 256;
pub const D_MAX: u32 = 8;
pub const P: u64 = (1 << 31) - 1;

fn val(x: u64) Q {
    return Q.fromU32Unchecked(@intCast(x), 0, 0, 0);
}
fn constant(ctx: *Context, x: u64) !Var {
    return ctx.constant(val(x));
}
pub fn guess(ctx: *Context, x: u64) !Var {
    return ctx.guess(val(x));
}
fn lin(ctx: *Context, a: Var, b: Var, scale: u64) !Var {
    // a + scale * b
    return ctx.add(a, try ctx.mul(b, try constant(ctx, scale)));
}

/// Witness of a range check: the claimed bits of v (LSB first).
pub fn bitsOf(value: u64, comptime n: u32) [n]bool {
    var out: [n]bool = undefined;
    for (&out, 0..) |*b, i| b.* = (value >> @intCast(i)) & 1 == 1;
    return out;
}
/// v in [0, 2^n): guessed Boolean bits that recompose to v.
pub fn rangeBits(ctx: *Context, v: Var, comptime n: u32, bits: [n]bool) !void {
    comptime std.debug.assert(n >= 1 and n <= 20);
    var acc = ctx.zero();
    for (bits, 0..) |bit, i| {
        const b = try ctx.guess(val(@intFromBool(bit)));
        try ctx.eq(try ctx.mul(b, b), b);
        acc = try lin(ctx, acc, b, @as(u64, 1) << @intCast(i));
    }
    try ctx.eq(acc, v);
}

/// Leaf segment index: k and MAX_PROOFS - 1 - k both in [0, 2^16).
pub const LeafIndexWitness = struct { k_bits: [16]bool, rest_bits: [16]bool };
pub fn leafIndexWitness(k: u64) LeafIndexWitness {
    return .{ .k_bits = bitsOf(k, 16), .rest_bits = bitsOf((MAX_PROOFS - 1) -% k, 16) };
}
pub fn leafIndex(ctx: *Context, k: Var, w: LeafIndexWitness) !void {
    try rangeBits(ctx, k, 16, w.k_bits);
    const rest = try ctx.sub(try constant(ctx, MAX_PROOFS - 1), k);
    try rangeBits(ctx, rest, 16, w.rest_bits);
}

/// One child's interval (seg_lo, seg_hi) wires.
pub const Interval = struct { lo: Var, hi: Var };
pub const IntervalWitness = struct { span_bits: [16]bool, rest_bits: [16]bool };
pub fn intervalWitness(lo: u64, hi: u64) IntervalWitness {
    return .{ .span_bits = bitsOf(hi -% lo, 16), .rest_bits = bitsOf((MAX_PROOFS - 1) -% hi, 16) };
}
/// Every child: hi - lo and MAX_PROOFS - 1 - hi in [0, 2^16); adjacent
/// children: lo[i+1] = hi[i] + 1. Returns the fold's (first lo, last hi).
pub fn foldInterval(ctx: *Context, children: []const Interval, witness: []const IntervalWitness) !Interval {
    if (children.len < 2 or children.len > 4 or witness.len != children.len) return error.InvalidFoldArity;
    for (children, witness) |c, w| {
        try rangeBits(ctx, try ctx.sub(c.hi, c.lo), 16, w.span_bits);
        try rangeBits(ctx, try ctx.sub(try constant(ctx, MAX_PROOFS - 1), c.hi), 16, w.rest_bits);
    }
    for (children[0 .. children.len - 1], children[1..]) |left, right| try ctx.eq(right.lo, try ctx.add(left.hi, ctx.one()));
    return .{ .lo = children[0].lo, .hi = children[children.len - 1].hi };
}

/// A canonical u32 mass as two u16 limbs (each range-checked by the caller's
/// u32 guess or by `massLimbs`).
pub const Mass = struct { lo: Var, hi: Var };
pub const MassWitness = struct {
    /// carry of the limb sum: S_lo = sum lo_i - carry * 2^16, carry in [0, 4).
    carry: u64,
    s_lo_bits: [16]bool,
    /// d = p - 1 - S as u16 limbs, and the limb-wise carry c2 of S + d.
    d_lo_bits: [16]bool,
    d_hi_bits: [16]bool,
    c2: bool,
    s_lo: u64,
    s_hi: u64,
    d_lo: u64,
    d_hi: u64,
};
/// Honest witness for `foldMass`; error.MassExceedsCharacteristic when the
/// integer sum is >= p (no honest witness exists then).
pub fn massWitness(children: []const u64) !MassWitness {
    var lo: u64 = 0;
    var hi: u64 = 0;
    var total: u64 = 0;
    for (children) |m| {
        if (m >= P) return error.NonCanonicalMass;
        lo += m & 0xFFFF;
        hi += m >> 16;
        total += m;
    }
    if (total >= P) return error.MassExceedsCharacteristic;
    const carry = lo >> 16;
    const s_lo = lo & 0xFFFF;
    const s_hi = hi + carry;
    const d = P - 1 - total;
    const d_lo = d & 0xFFFF;
    const d_hi = d >> 16;
    const c2 = s_lo + d_lo > 0xFFFF;
    return .{ .carry = carry, .s_lo_bits = bitsOf(s_lo, 16), .d_lo_bits = bitsOf(d_lo, 16), .d_hi_bits = bitsOf(d_hi, 16), .c2 = c2, .s_lo = s_lo, .s_hi = s_hi, .d_lo = d_lo, .d_hi = d_hi };
}
/// Integer sum of k masses, proven < p: S + d = p - 1 limb-wise with
/// d >= 0, so S <= p - 1. All intermediate values are < 2^20.
pub fn foldMass(ctx: *Context, children: []const Mass, w: MassWitness) !Mass {
    if (children.len < 2 or children.len > 4) return error.InvalidFoldArity;
    var sum_lo = ctx.zero();
    var sum_hi = ctx.zero();
    for (children) |c| {
        sum_lo = try ctx.add(sum_lo, c.lo);
        sum_hi = try ctx.add(sum_hi, c.hi);
    }
    // carry in [0, 4): two Boolean bits.
    const carry = try guess(ctx, w.carry);
    try rangeBits(ctx, carry, 2, bitsOf(w.carry, 2));
    const s_lo = try guess(ctx, w.s_lo);
    try rangeBits(ctx, s_lo, 16, w.s_lo_bits);
    try ctx.eq(try lin(ctx, s_lo, carry, 1 << 16), sum_lo);
    const s_hi = try ctx.add(sum_hi, carry);
    const d_lo = try guess(ctx, w.d_lo);
    try rangeBits(ctx, d_lo, 16, w.d_lo_bits);
    const d_hi = try guess(ctx, w.d_hi);
    try rangeBits(ctx, d_hi, 16, w.d_hi_bits);
    const c2 = try ctx.guess(val(@intFromBool(w.c2)));
    try ctx.eq(try ctx.mul(c2, c2), c2);
    // S_lo + d_lo = 0xFFFE + c2 * 2^16 ; S_hi + d_hi + c2 = 0x7FFF   (p - 1 = 0x7FFF_FFFE)
    try ctx.eq(try ctx.add(s_lo, d_lo), try lin(ctx, try constant(ctx, 0xFFFE), c2, 1 << 16));
    try ctx.eq(try ctx.add(try ctx.add(s_hi, d_hi), c2), try constant(ctx, 0x7FFF));
    return .{ .lo = s_lo, .hi = s_hi };
}

/// depth = 1 + max_i depth_i <= D_MAX. The max m is guessed: m - d_i in
/// [0, 2^4) for every child, prod (m - d_i) = 0, and D_MAX - (m + 1) in [0, 2^4).
pub const DepthWitness = struct { max: u64, gap_bits: [4][4]bool, slack_bits: [4]bool };
pub fn depthWitness(children: []const u64) DepthWitness {
    var m: u64 = 0;
    for (children) |d| m = @max(m, d);
    var w: DepthWitness = .{ .max = m, .gap_bits = undefined, .slack_bits = bitsOf((D_MAX) -% (m + 1), 4) };
    for (children, 0..) |d, i| w.gap_bits[i] = bitsOf(m -% d, 4);
    return w;
}
pub fn foldDepth(ctx: *Context, children: []const Var, w: DepthWitness) !Var {
    if (children.len < 2 or children.len > 4) return error.InvalidFoldArity;
    const m = try guess(ctx, w.max);
    var product = ctx.one();
    for (children, 0..) |d, i| {
        const gap = try ctx.sub(m, d);
        try rangeBits(ctx, gap, 4, w.gap_bits[i]);
        product = try ctx.mul(product, gap);
    }
    try ctx.eq(product, ctx.zero());
    const depth = try ctx.add(m, ctx.one());
    try rangeBits(ctx, try ctx.sub(try constant(ctx, D_MAX), depth), 4, w.slack_bits);
    return depth;
}

/// kappa = sum kappa_i with every kappa_i and the sum in [0, 2^9).
pub fn foldKappa(ctx: *Context, children: []const Var, values: []const u64) !Var {
    if (children.len < 2 or children.len > 4 or values.len != children.len) return error.InvalidFoldArity;
    var sum = ctx.zero();
    var total: u64 = 0;
    for (children, values) |c, v| {
        try rangeBits(ctx, c, 9, bitsOf(v, 9));
        sum = try ctx.add(sum, c);
        total +%= v;
    }
    try rangeBits(ctx, sum, 9, bitsOf(total, 9));
    return sum;
}

// ---------------------------------------------------------------------------
// Tests (W tier: one witness mutation each; the named constraint must fail).
// ---------------------------------------------------------------------------

fn fresh() !Context {
    return Context.init(std.testing.allocator, 0);
}
fn massVar(ctx: *Context, m: u64) !Mass {
    return .{ .lo = try guess(ctx, m & 0xFFFF), .hi = try guess(ctx, m >> 16) };
}

test "corpus Z04 fold mass: integer sum below p accepted; two children of p-1 have no witness; a wrapped sum is refused" {
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const values = [_]u64{ 15_713_510, 26_223_886, 0xFFFF, 1 << 29 };
        var kids: [4]Mass = undefined;
        for (&kids, values) |*k, v| k.* = try massVar(&ctx, v);
        const out = try foldMass(&ctx, &kids, try massWitness(&values));
        try std.testing.expect(try ctx.isCircuitValid());
        const total: u64 = values[0] + values[1] + values[2] + values[3];
        try std.testing.expectEqual(Q.fromU32Unchecked(@intCast(total & 0xFFFF), 0, 0, 0), ctx.get(out.lo));
        try std.testing.expectEqual(Q.fromU32Unchecked(@intCast(total >> 16), 0, 0, 0), ctx.get(out.hi));
    }
    // Two children of p - 1: the honest prover has no witness.
    try std.testing.expectError(error.MassExceedsCharacteristic, massWitness(&.{ P - 1, P - 1 }));
    // Two children of p - 1 (integer sum 2p - 2). The best attacker witness:
    // honest limb carry (S_lo = 0xFFFC, S_hi = 0xFFFF), d_lo = 2, and the d_hi
    // that satisfies S_hi + d_hi + c2 = 0x7FFF in the FIELD (p - 0x8000). Its
    // 16-bit range check is the constraint that fails.
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const kids = [_]Mass{ try massVar(&ctx, P - 1), try massVar(&ctx, P - 1) };
        const d_hi: u64 = P - 0x8000;
        const w = MassWitness{ .carry = 1, .s_lo = 0xFFFC, .s_lo_bits = bitsOf(0xFFFC, 16), .s_hi = 0xFFFF, .d_lo = 2, .d_lo_bits = bitsOf(2, 16), .d_hi = d_hi, .d_hi_bits = bitsOf(d_hi, 16), .c2 = false };
        _ = try foldMass(&ctx, &kids, w);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // The field-wrapped output S = p - 2 (what an M31 add would give) cannot
    // recompose the children's limb sum for any carry in [0, 4).
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const kids = [_]Mass{ try massVar(&ctx, P - 1), try massVar(&ctx, P - 1) };
        var w = try massWitness(&.{ P - 2, 0 });
        w.carry = 1;
        _ = try foldMass(&ctx, &kids, w);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // A sum of exactly p (p - 1 + 1) has no honest witness either.
    try std.testing.expectError(error.MassExceedsCharacteristic, massWitness(&.{ P - 1, 1 }));
}

test "corpus L05 Z05 leaf index: two-sided bound below MAX_PROOFS; k = MAX_PROOFS and k = p-1 refused" {
    for ([_]u64{ 0, 1, 255 }) |k| {
        var ctx = try fresh();
        defer ctx.deinit();
        try leafIndex(&ctx, try guess(&ctx, k), leafIndexWitness(k));
        try std.testing.expect(try ctx.isCircuitValid());
    }
    for ([_]u64{ 256, P - 1, 1 << 16 }) |k| {
        var ctx = try fresh();
        defer ctx.deinit();
        // The prover's best: bits of k mod 2^16 and of (255 - k) mod 2^16.
        try leafIndex(&ctx, try guess(&ctx, k), leafIndexWitness(k));
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "corpus Z05 fold interval: adjacency and per-child two-sided ranges; a wrapped seg_hi + 1 is refused" {
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const spans = [_][2]u64{ .{ 0, 3 }, .{ 4, 4 }, .{ 5, 9 } };
        var kids: [3]Interval = undefined;
        var w: [3]IntervalWitness = undefined;
        for (&kids, &w, spans) |*k, *wi, s| {
            k.* = .{ .lo = try guess(&ctx, s[0]), .hi = try guess(&ctx, s[1]) };
            wi.* = intervalWitness(s[0], s[1]);
        }
        const out = try foldInterval(&ctx, &kids, &w);
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expectEqual(val(0), ctx.get(out.lo));
        try std.testing.expectEqual(val(9), ctx.get(out.hi));
    }
    // A gap (S08/S10-style drop): [0,3] then [5,9].
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const kids = [_]Interval{ .{ .lo = try guess(&ctx, 0), .hi = try guess(&ctx, 3) }, .{ .lo = try guess(&ctx, 5), .hi = try guess(&ctx, 9) } };
        _ = try foldInterval(&ctx, &kids, &.{ intervalWitness(0, 3), intervalWitness(5, 9) });
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // Interior child with seg_hi = p - 1 so that seg_hi + 1 wraps to 0 in M31 (F6).
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const kids = [_]Interval{ .{ .lo = try guess(&ctx, 0), .hi = try guess(&ctx, P - 1) }, .{ .lo = try guess(&ctx, 0), .hi = try guess(&ctx, 5) } };
        _ = try foldInterval(&ctx, &kids, &.{ intervalWitness(0, P - 1), intervalWitness(0, 5) });
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // A child with lo > hi (negative span).
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const kids = [_]Interval{ .{ .lo = try guess(&ctx, 3), .hi = try guess(&ctx, 2) }, .{ .lo = try guess(&ctx, 3), .hi = try guess(&ctx, 5) } };
        _ = try foldInterval(&ctx, &kids, &.{ intervalWitness(3, 2), intervalWitness(3, 5) });
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "corpus Z06 fold depth: 1 + max <= D_MAX; a comb deeper than D_MAX and a lying max are refused" {
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const ds = [_]u64{ 0, 3, 2 };
        var kids: [3]Var = undefined;
        for (&kids, ds) |*k, d| k.* = try guess(&ctx, d);
        const depth = try foldDepth(&ctx, &kids, depthWitness(&ds));
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expectEqual(val(4), ctx.get(depth));
    }
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const ds = [_]u64{ D_MAX, 0 };
        const kids = [_]Var{ try guess(&ctx, ds[0]), try guess(&ctx, ds[1]) };
        _ = try foldDepth(&ctx, &kids, depthWitness(&ds));
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    {
        // Claim max = 1 when a child has depth 3 (understating the height).
        var ctx = try fresh();
        defer ctx.deinit();
        const ds = [_]u64{ 3, 1 };
        const kids = [_]Var{ try guess(&ctx, ds[0]), try guess(&ctx, ds[1]) };
        var w = depthWitness(&ds);
        w.max = 1;
        w.gap_bits[0] = bitsOf(@as(u64, 1) -% 3, 4);
        w.gap_bits[1] = bitsOf(0, 4);
        w.slack_bits = bitsOf(D_MAX - 2, 4);
        _ = try foldDepth(&ctx, &kids, w);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "fold kappa: sum of child leaf counts within 2^9; an out-of-range child count is refused" {
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const ks = [_]u64{ 4, 1, 6 };
        var kids: [3]Var = undefined;
        for (&kids, ks) |*k, v| k.* = try guess(&ctx, v);
        const sum = try foldKappa(&ctx, &kids, &ks);
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expectEqual(val(11), ctx.get(sum));
    }
    {
        var ctx = try fresh();
        defer ctx.deinit();
        const ks = [_]u64{ P - 1, 2 };
        const kids = [_]Var{ try guess(&ctx, ks[0]), try guess(&ctx, ks[1]) };
        _ = try foldKappa(&ctx, &kids, &ks);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
