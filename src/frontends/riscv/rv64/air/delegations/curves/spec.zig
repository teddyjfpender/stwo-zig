//! Admitted `ethereum_services_v3` curve and field operations (Wire35 program
//! kinds 5..11). Every operation is one call per truth row: a fixed set of
//! exact integer relations over little-endian byte limbs, each of the form
//!
//!     sum_t coef_t * a_t * b_t  +  sum_s coef_s * (v_s << 8 shift_s)  +  K*p  -  q*M  =  0
//!
//! where M is the field modulus p (constant) or a packet operand m (variable),
//! K*p is a comptime constant that keeps the quotient q non-negative, and every
//! vector is a byte vector (inputs/outputs inherit their U8 range from the
//! Word16 bridge through Wire35; witnesses, quotients and carries are checked
//! against a local BYTE table). This file is the single authority for the
//! relations and for the comptime bounds that make each carried identity an
//! integer identity (see `derive` and design/riscv-proving-stack/rv64-curve-services.md).
const std = @import("std");

pub const BN254_P: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
pub const BLS12_381_P: u384 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
/// Comptime/native big integer wide enough for every relation (< 2^1200).
pub const Big = u1536;
pub const MAX_LIMBS = 48;
/// Upper bound on relation coefficients (arith384_mont: 96 + 48 - 1 = 143).
pub const MAX_COEFFICIENTS = 160;
pub const M31: u64 = (1 << 31) - 1;

/// Wire35 program kind = Word16 bridge kind = the op's ordinal (5..11).
/// Kinds 1..4 are secp ADD/DOUBLE, SHA-256 and arith256_mod. The op set,
/// tags and packet geometry are owned by the execution ABI.
pub const exec = @import("../../../ethereum_services/curves.zig");
pub const Op = exec.Op;
pub const ALL = exec.ALL;
pub const COUNT = exec.COUNT;
pub const index = exec.index;
pub fn tag(op: Op) u32 {
    return @intCast(exec.tag(op));
}
pub const opOfTag = exec.opOfTag;

/// An L-byte operand: packet input i (packet bytes [i L, (i+1) L)), output j
/// (written over packet bytes [j L, (j+1) L)) or private witness w.
pub const Vec = union(enum) { in: u8, out: u8, wit: u8 };
/// `a * b * coef` when `b` is set, else `coef * (a << 8 shift)`.
pub const Term = struct { a: Vec, b: ?Vec = null, coef: i32, shift: u8 = 0 };
pub const Modulus = union(enum) { constant: Big, variable: u8 };
/// One-hot 16-bit chunk proof that a - b (or a) is nonzero; both canonical.
pub const NonZero = struct { a: Vec, b: ?Vec = null };

pub const Def = struct {
    /// Bytes per field element (32 or 48).
    limbs: usize,
    /// 32-byte packet coordinates bound by the bridge.
    coords: usize,
    /// Leading coordinates written (outputs overwrite inputs in place).
    written: usize,
    inputs: usize,
    outputs: usize,
    witnesses: usize,
    modulus: Modulus,
    relations: []const []const Term,
    /// Inputs proven canonical (< modulus); every output always is.
    canonical_inputs: []const u8 = &.{},
    nonzero: ?NonZero = null,
    /// Variable modulus only: m odd (low byte = 2 h + 1, h < 128).
    odd_modulus: bool = false,
    /// Variable modulus only: explicit quotient width (see `def`).
    q_bytes: ?usize = null,
};

fn t(a: Vec, b: ?Vec, coef: i32) Term {
    return .{ .a = a, .b = b, .coef = coef };
}
fn s(a: Vec, coef: i32, shift: u8) Term {
    return .{ .a = a, .coef = coef, .shift = shift };
}
const in = struct {
    fn v(i: u8) Vec {
        return .{ .in = i };
    }
}.v;
const out = struct {
    fn v(i: u8) Vec {
        return .{ .out = i };
    }
}.v;
const wit = struct {
    fn v(i: u8) Vec {
        return .{ .wit = i };
    }
}.v;

/// Admitted packets are INLINE and 32-byte aligned (the candidates passed
/// pointers): the Word16 bridge binds contiguous 32-byte coordinates at a0.
/// Outputs overwrite the leading inputs in place.
///   bn254_g1_add      [x1 y1 x2 y2]            -> [x3 y3 x2 y2]      (plain form)
///   bn254_g1_double   [x y]                     -> [x3 y3]
///   bn254_fp2_mul     [a0 a1 b0 b1]             -> [c0 c1 b0 b1]
///   bls12_381_fp2_mul [a0 a1 b0 b1] (48 B each) -> [c0 c1 b0 b1]      (Montgomery: c = a b 2^-384)
///   arith384_mont     [a b m pad16]             -> [r b m pad16]      (r = a b 2^-384 mod m, m odd)
///   bls12_381_g1_add  [x1 y1 x2 y2] (48 B)      -> [x3 y3 x2 y2]      (Montgomery residues)
///   bls12_381_g1_double [x y] (48 B)            -> [x3 y3]
/// Relations (mod the modulus; K*p is added automatically for a constant p):
///   affine add:    l (x2 - x1) = y2 - y1,  l^2 = x1 + x2 + x3,  l (x1 - x3) = y1 + y3
///   affine double: 2 l y = 3 x^2,          l^2 = 2 x + x3,       l (x - x3) = y + y3
///   Montgomery forms multiply every linear side by R = 2^384 (shift 48), with
///   l the Montgomery residue of the slope (R cancels in the quadratic sides).
pub fn def(comptime op: Op) Def {
    const bls: Big = BLS12_381_P;
    const bn: Big = BN254_P;
    return switch (op) {
        .bn254_g1_add => .{ .limbs = 32, .coords = 4, .written = 2, .inputs = 4, .outputs = 2, .witnesses = 1, .modulus = .{ .constant = bn }, .relations = &.{
            &.{ t(wit(0), in(2), 1), t(wit(0), in(0), -1), s(in(3), -1, 0), s(in(1), 1, 0) },
            &.{ t(wit(0), wit(0), 1), s(in(0), -1, 0), s(in(2), -1, 0), s(out(0), -1, 0) },
            &.{ t(wit(0), in(0), 1), t(wit(0), out(0), -1), s(in(1), -1, 0), s(out(1), -1, 0) },
        }, .canonical_inputs = &.{ 0, 1, 2, 3 }, .nonzero = .{ .a = in(2), .b = in(0) } },
        .bn254_g1_double => .{ .limbs = 32, .coords = 2, .written = 2, .inputs = 2, .outputs = 2, .witnesses = 1, .modulus = .{ .constant = bn }, .relations = &.{
            &.{ t(wit(0), in(1), 2), t(in(0), in(0), -3) },
            &.{ t(wit(0), wit(0), 1), s(in(0), -2, 0), s(out(0), -1, 0) },
            &.{ t(wit(0), in(0), 1), t(wit(0), out(0), -1), s(in(1), -1, 0), s(out(1), -1, 0) },
        }, .canonical_inputs = &.{ 0, 1 }, .nonzero = .{ .a = in(1) } },
        .bn254_fp2_mul => .{ .limbs = 32, .coords = 4, .written = 2, .inputs = 4, .outputs = 2, .witnesses = 0, .modulus = .{ .constant = bn }, .relations = &.{
            &.{ t(in(0), in(2), 1), t(in(1), in(3), -1), s(out(0), -1, 0) },
            &.{ t(in(0), in(3), 1), t(in(1), in(2), 1), s(out(1), -1, 0) },
        } },
        .bls12_381_fp2_mul => .{ .limbs = 48, .coords = 6, .written = 3, .inputs = 4, .outputs = 2, .witnesses = 0, .modulus = .{ .constant = bls }, .relations = &.{
            &.{ t(in(0), in(2), 1), t(in(1), in(3), -1), s(out(0), -1, 48) },
            &.{ t(in(0), in(3), 1), t(in(1), in(2), 1), s(out(1), -1, 48) },
        } },
        // a b + m 2^384 = r 2^384 + q m with r < m: q < 2^768 because
        // a b <= (2^384 - 1)^2 and r 2^384 >= 0, m >= 1, so 96 bytes suffice.
        .arith384_mont => .{ .limbs = 48, .coords = 5, .written = 2, .inputs = 3, .outputs = 1, .witnesses = 0, .modulus = .{ .variable = 2 }, .relations = &.{
            &.{ t(in(0), in(1), 1), s(in(2), 1, 48), s(out(0), -1, 48) },
        }, .odd_modulus = true, .q_bytes = 96 },
        .bls12_381_g1_add => .{ .limbs = 48, .coords = 6, .written = 3, .inputs = 4, .outputs = 2, .witnesses = 1, .modulus = .{ .constant = bls }, .relations = &.{
            &.{ t(wit(0), in(2), 1), t(wit(0), in(0), -1), s(in(3), -1, 48), s(in(1), 1, 48) },
            &.{ t(wit(0), wit(0), 1), s(in(0), -1, 48), s(in(2), -1, 48), s(out(0), -1, 48) },
            &.{ t(wit(0), in(0), 1), t(wit(0), out(0), -1), s(in(1), -1, 48), s(out(1), -1, 48) },
        }, .canonical_inputs = &.{ 0, 1, 2, 3 }, .nonzero = .{ .a = in(2), .b = in(0) } },
        .bls12_381_g1_double => .{ .limbs = 48, .coords = 3, .written = 3, .inputs = 2, .outputs = 2, .witnesses = 1, .modulus = .{ .constant = bls }, .relations = &.{
            &.{ t(wit(0), in(1), 2), t(in(0), in(0), -3) },
            &.{ t(wit(0), wit(0), 1), s(in(0), -2, 48), s(out(0), -1, 48) },
            &.{ t(wit(0), in(0), 1), t(wit(0), out(0), -1), s(in(1), -1, 48), s(out(1), -1, 48) },
        }, .canonical_inputs = &.{ 0, 1 }, .nonzero = .{ .a = in(1) } },
    };
}

/// secp256k1 homogeneous RCB ADD/DOUBLE (Wire35 program kinds 1/2) as a
/// one-call-per-row truth: the selectable `row_v1` replacement of the RCB
/// product/linear providers (`secp256k1/layout.zig`). It is not an execution
/// op: the packet ABI, tags and Wire35 IDs are the secp service's own
/// (`ethereum_services/secp256k1.zig`, `word16_bridge/types.zig`), and every
/// output equals that program's canonical result.
pub const secp = @import("../../../ethereum_services/secp256k1.zig");
pub const SecpKind = secp.Kind;
pub const SECP256K1_P: u256 = secp.MODULUS;

/// RCB complete homogeneous formulas (k256 0.13.4, b3 = 21) written as exact
/// integer relations over byte limbs. Raw packet coordinates are any 256-bit
/// words: every relation is taken mod p, so they enter by their residue,
/// exactly as the program's `reduce_once` (raw < 2^256 < 2p). Witnesses are
/// arbitrary byte vectors bound by their own relation mod p; only the three
/// outputs are proven canonical.
///   ADD [X1 Y1 Z1 X2 Y2 Z2] -> [X3 Y3 Z3 X2 Y2 Z2]
///     xx = X1 X2, yy = Y1 Y2, zz = Z1 Z2,
///     xy = X1 Y2 + Y1 X2, yz = Y1 Z2 + Z1 Y2, xz = X1 Z2 + Z1 X2,
///     X3 = xy (yy - 21 zz) - 21 yz xz,
///     Y3 = (yy + 21 zz)(yy - 21 zz) + 63 xx xz = yy^2 - 441 zz^2 + 63 xx xz,
///     Z3 = yz (yy + 21 zz) + 3 xx xy.
///   DOUBLE [X Y Z] -> [X3 Y3 Z3]
///     yy = Y^2, zz = Z^2, xy = X Y, yz = Y Z, ym = yy - 63 zz,
///     X3 = 2 xy ym,
///     Y3 = ym (yy + 21 zz) + 168 yy zz,
///     Z3 = 8 yy yz.
pub fn secpDef(comptime kind: SecpKind) Def {
    const p: Big = SECP256K1_P;
    return switch (kind) {
        .add => .{ .limbs = 32, .coords = 6, .written = 3, .inputs = 6, .outputs = 3, .witnesses = 6, .modulus = .{ .constant = p }, .relations = &.{
            &.{ t(in(0), in(3), 1), s(wit(0), -1, 0) },
            &.{ t(in(1), in(4), 1), s(wit(1), -1, 0) },
            &.{ t(in(2), in(5), 1), s(wit(2), -1, 0) },
            &.{ t(in(0), in(4), 1), t(in(1), in(3), 1), s(wit(3), -1, 0) },
            &.{ t(in(1), in(5), 1), t(in(2), in(4), 1), s(wit(4), -1, 0) },
            &.{ t(in(0), in(5), 1), t(in(2), in(3), 1), s(wit(5), -1, 0) },
            &.{ t(wit(3), wit(1), 1), t(wit(3), wit(2), -21), t(wit(4), wit(5), -21), s(out(0), -1, 0) },
            &.{ t(wit(1), wit(1), 1), t(wit(2), wit(2), -441), t(wit(0), wit(5), 63), s(out(1), -1, 0) },
            &.{ t(wit(4), wit(1), 1), t(wit(4), wit(2), 21), t(wit(0), wit(3), 3), s(out(2), -1, 0) },
        } },
        .double => .{ .limbs = 32, .coords = 3, .written = 3, .inputs = 3, .outputs = 3, .witnesses = 5, .modulus = .{ .constant = p }, .relations = &.{
            &.{ t(in(1), in(1), 1), s(wit(0), -1, 0) },
            &.{ t(in(2), in(2), 1), s(wit(1), -1, 0) },
            &.{ t(in(0), in(1), 1), s(wit(2), -1, 0) },
            &.{ t(in(1), in(2), 1), s(wit(3), -1, 0) },
            &.{ s(wit(0), 1, 0), s(wit(1), -63, 0), s(wit(4), -1, 0) },
            &.{ t(wit(2), wit(4), 2), s(out(0), -1, 0) },
            &.{ t(wit(4), wit(0), 1), t(wit(4), wit(1), 21), t(wit(0), wit(1), 168), s(out(1), -1, 0) },
            &.{ t(wit(0), wit(3), 8), s(out(2), -1, 0) },
        } },
    };
}

/// Generic truth key: a curve/field `Op` or a secp `SecpKind`. Every
/// layout/equation/trace/component authority below is keyed by it.
pub fn checkKey(comptime K: type) void {
    if (K != Op and K != SecpKind) @compileError("curve truth key must be curves.Op or secp256k1 Kind");
}
pub fn defOf(comptime key: anytype) Def {
    checkKey(@TypeOf(key));
    return if (@TypeOf(key) == Op) def(key) else secpDef(key);
}
/// Wire35 program kind (the Op ordinal 5..11, or the secp kind 1/2).
pub fn kindOf(comptime key: anytype) u32 {
    checkKey(@TypeOf(key));
    return @intFromEnum(key);
}
pub fn tagOf(comptime key: anytype) u32 {
    checkKey(@TypeOf(key));
    return if (@TypeOf(key) == Op) tag(key) else switch (key) {
        .add => 0x20011,
        .double => 0x20012,
    };
}
/// Wire35 ID of fraction `id`: input coordinates are `0..coords-1`; written
/// coordinate c is `coords + c` for curve ops and the RCB program's output
/// wire for secp (the IDs the Word16 bridge publishes, `outputWire`).
pub fn wireLabel(comptime key: anytype, id: usize) u32 {
    const d = comptime defOf(key);
    if (@TypeOf(key) == Op or id < d.coords) return @intCast(id);
    return secp.get(key).outputs[id - d.coords];
}

pub fn byteLen(x: Big) usize {
    if (x == 0) return 1;
    return (@bitSizeOf(Big) - @clz(x) + 7) / 8;
}
pub fn limbOf(x: Big, k: usize) u8 {
    return @truncate(x >> @intCast(8 * k));
}
fn absCoef(c: i32) Big {
    return @intCast(@abs(c));
}

/// Comptime geometry of one relation, including the exactness certificate.
pub const RelationGeometry = struct {
    /// K (K*p is added on the positive side; 0 for a variable modulus).
    k: Big,
    kp: Big,
    q_bytes: usize,
    coefficients: usize,
    /// Coefficients per carried group (1 or 2) and the group radix 256^group.
    group: usize,
    groups: usize,
    carries: usize,
    /// Carries lie in [-2^(carry_bits-1), 2^(carry_bits-1)), encoded as
    /// carry_bytes bytes of (carry + 2^(carry_bits-1) * active); the top byte
    /// is below 2^top_bits (an extra BYTE query when top_bits < 8).
    carry_bits: u32,
    carry_bytes: usize,
    top_bits: u32,
    /// max_j |G_j| and the honest carry bound (both certified < 2^31 - 1).
    group_bound: u64,
    honest_carry: u64,
};

fn modulusLimb(comptime d: Def, k: usize) u64 {
    return switch (d.modulus) {
        .constant => |p| if (k < d.limbs) limbOf(p, k) else 0,
        .variable => if (k < d.limbs) 255 else 0,
    };
}

pub fn deriveRelation(comptime d: Def, comptime terms: []const Term) RelationGeometry {
    @setEvalBranchQuota(50_000_000);
    const L = d.limbs;
    const vmax: Big = (@as(Big, 1) << @intCast(8 * L)) - 1;
    var pos: Big = 0;
    var neg: Big = 0;
    var span: usize = 0;
    for (terms) |term| {
        const magnitude = if (term.b != null) absCoef(term.coef) * vmax * vmax else absCoef(term.coef) * (vmax << @intCast(8 * @as(usize, term.shift)));
        if (term.b != null and term.shift != 0) @compileError("shifted products are not supported");
        if (term.coef > 0) pos += magnitude else neg += magnitude;
        span = @max(span, if (term.b != null) 2 * L - 1 else @as(usize, term.shift) + L);
    }
    var g: RelationGeometry = undefined;
    switch (d.modulus) {
        .constant => |p| {
            g.k = (neg + p - 1) / p;
            g.kp = g.k * p;
            g.q_bytes = byteLen((pos + g.kp) / p);
        },
        .variable => {
            g.k = 0;
            g.kp = 0;
            g.q_bytes = d.q_bytes orelse @compileError("variable modulus needs an explicit quotient width");
        },
    }
    g.coefficients = @max(span, @max(g.q_bytes + L - 1, if (g.kp == 0) 0 else byteLen(g.kp)));
    if (g.coefficients > MAX_COEFFICIENTS) @compileError("relation too wide");
    // Per-coefficient maxima of the positive and negative parts.
    var p_max: [MAX_COEFFICIENTS]u64 = @splat(0);
    var n_max: [MAX_COEFFICIENTS]u64 = @splat(0);
    for (terms) |term| {
        const c: u64 = @intCast(@abs(term.coef));
        const into = if (term.coef > 0) &p_max else &n_max;
        if (term.b != null) {
            for (0..2 * L - 1) |k| {
                const lo: u64 = if (k + 1 > L) k + 1 - L else 0;
                const hi: u64 = @min(k, L - 1);
                into[k] += c * 255 * 255 * (hi - lo + 1);
            }
        } else for (0..L) |i| {
            into[term.shift + i] += c * 255;
        }
    }
    for (0..g.coefficients) |k| p_max[k] += limbOf(g.kp, k);
    for (0..g.q_bytes) |i| for (0..L) |j| {
        n_max[i + j] += 255 * modulusLimb(d, j);
    };
    var best: ?RelationGeometry = null;
    for ([_]usize{ 2, 1 }) |group| {
        if (best != null) break;
        const radix: u64 = @as(u64, 1) << @intCast(8 * group);
        const groups = (g.coefficients + group - 1) / group;
        var group_bound: u64 = 0;
        var honest: Big = 0;
        var partial: Big = 0;
        for (0..groups) |j| {
            var gp: u64 = 0;
            var gn: u64 = 0;
            for (0..group) |offset| {
                const k = group * j + offset;
                if (k >= g.coefficients) continue;
                gp += p_max[k] << @intCast(8 * offset);
                gn += n_max[k] << @intCast(8 * offset);
                partial += @as(Big, @max(p_max[k], n_max[k])) << @intCast(8 * k);
            }
            group_bound = @max(group_bound, @max(gp, gn));
            if (j + 1 < groups) honest = @max(honest, partial >> @intCast(8 * group * (j + 1)));
        }
        var bits: u32 = 1;
        while ((@as(Big, 1) << @intCast(bits - 1)) <= honest) bits += 1;
        const half: u64 = @as(u64, 1) << @intCast(bits - 1);
        if (group_bound + half * (radix + 1) < M31) {
            var r = g;
            r.group = group;
            r.groups = groups;
            r.carries = groups - 1;
            r.carry_bits = bits;
            r.carry_bytes = (bits + 7) / 8;
            r.top_bits = bits - 8 * @as(u32, @intCast(r.carry_bytes - 1));
            r.group_bound = group_bound;
            r.honest_carry = @intCast(honest);
            best = r;
        }
    }
    return best orelse @compileError("no exact carry geometry for relation");
}

comptime {
    for (ALL) |op| {
        const d = def(op);
        if (d.coords != exec.coords(op) or d.written != exec.writtenCoords(op)) @compileError("curve AIR/execution packet geometry drift");
        if (d.outputs * d.limbs > 32 * d.written or d.inputs * d.limbs > 32 * d.coords) @compileError("curve packet does not hold its operands");
    }
}
