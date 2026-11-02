//! Admitted `ethereum_services_v3` curve and field services (tags of the
//! execution-only candidates, inline 32-byte aligned packets). Pure witness:
//! the curves truth AIR re-derives every output from carried relations,
//! canonical checks and the nonzero proof.
//!
//! Packets (little-endian u64 limbs, 4 per BN254 value, 6 per 384-bit value;
//! outputs overwrite the leading operands in place):
//!   0x0003_0100 bn254_g1_add        [x1 y1 x2 y2]        -> x3 y3 (x1 != x2, all < p)
//!   0x0003_0101 bn254_g1_double     [x y]                -> x3 y3 (y != 0, all < p)
//!   0x0003_0102 bn254_fp2_mul       [a0 a1 b0 b1]        -> c0 c1 (plain form, any inputs)
//!   0x0003_0112 bls12_381_fp2_mul   [a0 a1 b0 b1]        -> c0 c1 (c = a b 2^-384 mod p)
//!   0x0003_0121 arith384_mont       [a b m pad(16 B)]    -> r     (r = a b 2^-384 mod m, m odd)
//!   0x0003_0110 bls12_381_g1_add    [x1 y1 x2 y2]        -> x3 y3 (Montgomery residues)
//!   0x0003_0111 bls12_381_g1_double [x y]                -> x3 y3 (Montgomery residues)
//! A violated precondition traps `CurveServiceDomain` with memory unchanged.
const std = @import("std");
const C = @import("candidate_curves.zig");

pub const Op = enum(u8) {
    bn254_g1_add = 5,
    bn254_g1_double = 6,
    bn254_fp2_mul = 7,
    bls12_381_fp2_mul = 8,
    arith384_mont = 9,
    bls12_381_g1_add = 10,
    bls12_381_g1_double = 11,
};
pub const ALL = [_]Op{ .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont, .bls12_381_g1_add, .bls12_381_g1_double };
pub const COUNT = ALL.len;
pub const MAX_WORDS = 24;

pub fn index(op: Op) usize {
    return @intFromEnum(op) - 5;
}
pub fn tag(op: Op) u64 {
    return switch (op) {
        .bn254_g1_add => C.BN254_G1_ADD_TAG,
        .bn254_g1_double => C.BN254_G1_DOUBLE_TAG,
        .bn254_fp2_mul => C.BN254_FP2_MUL_TAG,
        .bls12_381_fp2_mul => C.BLS12_381_FP2_MUL_TAG,
        .arith384_mont => C.ARITH384_MONT_TAG,
        .bls12_381_g1_add => C.BLS12_381_G1_ADD_TAG,
        .bls12_381_g1_double => C.BLS12_381_G1_DOUBLE_TAG,
    };
}
comptime {
    const profile = @import("../execution_profile.zig");
    for (ALL, profile.CURVE_TAGS) |op, t| if (tag(op) != t) @compileError("curve tag roster drift");
}
pub fn opOfTag(raw: u64) ?Op {
    for (ALL) |op| if (tag(op) == raw) return op;
    return null;
}
/// 32-byte packet coordinates (the bridge binds 4 words per coordinate).
pub fn coords(op: Op) usize {
    return switch (op) {
        .bn254_g1_add, .bn254_fp2_mul => 4,
        .bn254_g1_double => 2,
        .bls12_381_fp2_mul, .bls12_381_g1_add => 6,
        .arith384_mont => 5,
        .bls12_381_g1_double => 3,
    };
}
/// Leading coordinates written (the bridge's write set).
pub fn writtenCoords(op: Op) usize {
    return switch (op) {
        .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .arith384_mont => 2,
        .bls12_381_fp2_mul, .bls12_381_g1_add, .bls12_381_g1_double => 3,
    };
}
pub fn words(op: Op) usize {
    return 4 * coords(op);
}
pub fn writtenWords(op: Op) usize {
    return 4 * writtenCoords(op);
}

fn value(comptime T: type, packet: []const u64, at: usize) T {
    const limbs = @bitSizeOf(T) / 64;
    var x: T = 0;
    for (0..limbs) |i| x |= @as(T, packet[at * limbs + i]) << @intCast(64 * i);
    return x;
}
fn store(comptime T: type, out: []u64, at: usize, x: T) void {
    const limbs = @bitSizeOf(T) / 64;
    for (0..limbs) |i| out[at * limbs + i] = @truncate(x >> @intCast(64 * i));
}
const R384: u384 = @intCast((@as(u768, 1) << 384) % C.BLS12_381_P);

/// The packet after one call (words beyond the outputs unchanged), or
/// CurveServiceDomain when a precondition fails.
pub fn execute(op: Op, before: []const u64) error{CurveServiceDomain}![MAX_WORDS]u64 {
    std.debug.assert(before.len == words(op));
    var after: [MAX_WORDS]u64 = @splat(0);
    @memcpy(after[0..before.len], before);
    switch (op) {
        .bn254_g1_add, .bn254_g1_double => {
            const n: usize = if (op == .bn254_g1_add) 4 else 2;
            var v: [4]u256 = undefined;
            for (0..n) |i| {
                v[i] = value(u256, before, i);
                if (v[i] >= C.BN254_P) return error.CurveServiceDomain;
            }
            const r = if (op == .bn254_g1_add) blk: {
                if (v[0] == v[2]) return error.CurveServiceDomain;
                break :blk C.affineAdd(C.Bn254, u256, v[0], v[1], v[2], v[3]);
            } else blk: {
                if (v[1] == 0) return error.CurveServiceDomain;
                break :blk C.affineDouble(C.Bn254, u256, v[0], v[1]);
            };
            store(u256, &after, 0, r[0]);
            store(u256, &after, 1, r[1]);
        },
        .bn254_fp2_mul => {
            var v: [4]u256 = undefined;
            for (&v, 0..) |*x, i| x.* = C.Bn254.reduce(value(u256, before, i));
            const r = C.fp2Mul(C.Bn254, u256, .{ v[0], v[1] }, .{ v[2], v[3] });
            store(u256, &after, 0, r[0]);
            store(u256, &after, 1, r[1]);
        },
        .bls12_381_fp2_mul => {
            var v: [4]u384 = undefined;
            for (&v, 0..) |*x, i| x.* = C.Bls.reduce(value(u384, before, i));
            const r = C.fp2Mul(C.Bls, u384, .{ v[0], v[1] }, .{ v[2], v[3] });
            const ri = C.Bls.inv(R384);
            store(u384, &after, 0, C.Bls.mul(r[0], ri));
            store(u384, &after, 1, C.Bls.mul(r[1], ri));
        },
        .arith384_mont => {
            const m = value(u384, before, 2);
            if (m & 1 == 0) return error.CurveServiceDomain;
            store(u384, &after, 0, C.mont384(value(u384, before, 0), value(u384, before, 1), m));
        },
        .bls12_381_g1_add, .bls12_381_g1_double => {
            const n: usize = if (op == .bls12_381_g1_add) 4 else 2;
            const ri = C.Bls.inv(R384);
            var v: [4]u384 = undefined;
            var plain: [4]u384 = undefined;
            for (0..n) |i| {
                v[i] = value(u384, before, i);
                if (v[i] >= C.BLS12_381_P) return error.CurveServiceDomain;
                plain[i] = C.Bls.mul(v[i], ri);
            }
            const r = if (op == .bls12_381_g1_add) blk: {
                if (v[0] == v[2]) return error.CurveServiceDomain;
                break :blk C.affineAdd(C.Bls, u384, plain[0], plain[1], plain[2], plain[3]);
            } else blk: {
                if (v[1] == 0) return error.CurveServiceDomain;
                break :blk C.affineDouble(C.Bls, u384, plain[0], plain[1]);
            };
            store(u384, &after, 0, C.Bls.mul(r[0], R384));
            store(u384, &after, 1, C.Bls.mul(r[1], R384));
        },
    }
    return after;
}

test "admitted inline packets agree with the candidate pointer-packet executor" {
    const memory = @import("../memory.zig");
    var prng = std.Random.DefaultPrng.init(0x30100);
    const rng = prng.random();
    const base: u64 = 0x10000;
    var mem = memory.Memory.init(std.testing.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = base, .size = 0x4000, .permissions = .{ .read = true, .write = true } });
    for (ALL) |op| {
        var done: usize = 0;
        while (done < 24) {
            var packet: [MAX_WORDS]u64 = @splat(0);
            for (packet[0..words(op)]) |*w| w.* = rng.int(u64);
            // Mostly-canonical operands: clear the top bits of each value.
            const limbs: usize = if (@intFromEnum(op) <= 7) 4 else 6;
            const values = @min(4, words(op) / limbs);
            for (0..values) |i| packet[i * limbs + limbs - 1] &= if (limbs == 4) 0x0fffffffffffffff else 0x00ffffffffffffff;
            if (op == .arith384_mont) packet[12] |= 1;
            const after = execute(op, packet[0..words(op)]) catch continue;
            // Candidate: operands at separate addresses, pointer packet at base.
            const k = C.kindOf(tag(op)).?;
            const operand = base + 0x100;
            for (0..words(op)) |i| try mem.storeWords(operand + 8 * i, &.{packet[i]});
            const out = base + 0x800;
            const ptrs: []const u64 = switch (op) {
                .bn254_g1_add, .bn254_fp2_mul => &.{ out, operand, operand + 64 },
                .bn254_g1_double => &.{ out, operand },
                .bls12_381_fp2_mul, .bls12_381_g1_add => &.{ out, operand, operand + 96 },
                .bls12_381_g1_double => &.{ out, operand },
                .arith384_mont => &.{ operand, operand + 48, operand + 96, out },
            };
            try mem.storeWords(base, ptrs);
            _ = try C.execute(k, base, &mem);
            const out_words = if (op == .arith384_mont) @as(usize, 6) else 2 * limbs;
            for (0..out_words) |i| try std.testing.expectEqual(try mem.load(out + 8 * i, 8), after[i]);
            for (out_words..words(op)) |i| try std.testing.expectEqual(packet[i], after[i]);
            done += 1;
        }
    }
}
