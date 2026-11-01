//! Native semantics and witness rows of the curve/field operations. This is
//! producer advice only: the AIR re-derives every output from the carried
//! relations, the canonical checks and the nonzero proof, and Wire35 binds the
//! packet bytes to guest RAM.
const std = @import("std");
const core = @import("stwo_core");
const spec = @import("spec.zig");
const LayoutOf = @import("layout.zig").Layout;
const M31 = core.fields.m31.M31;
const Big = spec.Big;
const SBig = std.meta.Int(.signed, @bitSizeOf(Big) + 1);

pub const Error = error{CurveDomain};

/// Inverse of a modulo odd m, gcd(a, m) = 1, a != 0 mod m (binary extended Euclid).
pub fn invMod(comptime T: type, a: T, m: T) T {
    const W = std.meta.Int(.unsigned, @bitSizeOf(T) + 1);
    var u = a % m;
    var v = m;
    var x1: T = 1;
    var x2: T = 0;
    while (u != 1 and v != 1) {
        while (u & 1 == 0) {
            u >>= 1;
            x1 = if (x1 & 1 == 0) x1 >> 1 else @intCast((@as(W, x1) + m) >> 1);
        }
        while (v & 1 == 0) {
            v >>= 1;
            x2 = if (x2 & 1 == 0) x2 >> 1 else @intCast((@as(W, x2) + m) >> 1);
        }
        if (u >= v) {
            u -= v;
            x1 = if (x1 >= x2) x1 - x2 else m - (x2 - x1);
        } else {
            v -= u;
            x2 = if (x2 >= x1) x2 - x1 else m - (x1 - x2);
        }
    }
    return if (u == 1) x1 else x2;
}

/// Prime-field arithmetic over canonical values.
pub fn Field(comptime T: type, comptime p: T) type {
    const W = std.meta.Int(.unsigned, 2 * @bitSizeOf(T));
    return struct {
        pub fn add(a: T, b: T) T {
            const x = @as(W, a) + b;
            return @intCast(if (x >= p) x - p else x);
        }
        pub fn sub(a: T, b: T) T {
            return if (a >= b) a - b else p - (b - a);
        }
        pub fn mul(a: T, b: T) T {
            return @intCast(@as(W, a) * b % p);
        }
        pub fn inv(a: T) T {
            return invMod(T, a, p);
        }
    };
}
pub const Bn = Field(u256, spec.BN254_P);
pub const Bls = Field(u384, spec.BLS12_381_P);
/// 2^384 mod p and its inverse (BLS12-381 Montgomery radix).
pub const BLS_R: u384 = @intCast((@as(u768, 1) << 384) % spec.BLS12_381_P);
pub const BLS_R_INV: u384 = blk: {
    @setEvalBranchQuota(10_000_000);
    break :blk invMod(u384, BLS_R, spec.BLS12_381_P);
};
pub fn blsRInv() u384 {
    return BLS_R_INV;
}

fn affineAdd(comptime F: type, comptime T: type, x1: T, y1: T, x2: T, y2: T) [3]T {
    const l = F.mul(F.sub(y2, y1), F.inv(F.sub(x2, x1)));
    const x3 = F.sub(F.sub(F.mul(l, l), x1), x2);
    return .{ x3, F.sub(F.mul(l, F.sub(x1, x3)), y1), l };
}
fn affineDouble(comptime F: type, comptime T: type, x: T, y: T) [3]T {
    const xx = F.mul(x, x);
    const l = F.mul(F.add(F.add(xx, xx), xx), F.inv(F.add(y, y)));
    const x3 = F.sub(F.mul(l, l), F.add(x, x));
    return .{ x3, F.sub(F.mul(l, F.sub(x, x3)), y), l };
}

pub fn Native(comptime op: spec.Op) type {
    return struct {
        pub const L = LayoutOf(op);
        const d = L.DEF;
        pub const Packet = [L.PACKET_BYTES]u8;
        pub const Row = [L.MAIN]u32;
        pub const Witness = struct { out: [d.outputs]Big, wit: [d.witnesses]Big };

        pub fn operand(packet: *const Packet, i: usize) Big {
            var x: Big = 0;
            for (0..d.limbs) |b| x |= @as(Big, packet[i * d.limbs + b]) << @intCast(8 * b);
            return x;
        }
        fn modulusOf(packet: *const Packet) Big {
            return switch (d.modulus) {
                .constant => |p| p,
                .variable => |m| operand(packet, m),
            };
        }
        /// ABI semantics; CurveDomain when a precondition fails (the AIR is
        /// then unsatisfiable, and the executor traps).
        pub fn compute(packet: *const Packet) Error!Witness {
            var in: [d.inputs]Big = undefined;
            for (&in, 0..) |*x, i| x.* = operand(packet, i);
            for (d.canonical_inputs) |i| if (in[i] >= modulusOf(packet)) return error.CurveDomain;
            var w: Witness = undefined;
            switch (op) {
                .bn254_g1_add => {
                    if (in[0] == in[2]) return error.CurveDomain;
                    const r = affineAdd(Bn, u256, @intCast(in[0]), @intCast(in[1]), @intCast(in[2]), @intCast(in[3]));
                    w.out = .{ r[0], r[1] };
                    w.wit = .{r[2]};
                },
                .bn254_g1_double => {
                    if (in[1] == 0) return error.CurveDomain;
                    const r = affineDouble(Bn, u256, @intCast(in[0]), @intCast(in[1]));
                    w.out = .{ r[0], r[1] };
                    w.wit = .{r[2]};
                },
                .bn254_fp2_mul => {
                    const p = spec.BN254_P;
                    const a0: u256 = @intCast(in[0] % p);
                    const a1: u256 = @intCast(in[1] % p);
                    const b0: u256 = @intCast(in[2] % p);
                    const b1: u256 = @intCast(in[3] % p);
                    w.out = .{ Bn.sub(Bn.mul(a0, b0), Bn.mul(a1, b1)), Bn.add(Bn.mul(a0, b1), Bn.mul(a1, b0)) };
                },
                .bls12_381_fp2_mul => {
                    const p = spec.BLS12_381_P;
                    const a0: u384 = @intCast(in[0] % p);
                    const a1: u384 = @intCast(in[1] % p);
                    const b0: u384 = @intCast(in[2] % p);
                    const b1: u384 = @intCast(in[3] % p);
                    const ri = blsRInv();
                    w.out = .{ Bls.mul(Bls.sub(Bls.mul(a0, b0), Bls.mul(a1, b1)), ri), Bls.mul(Bls.add(Bls.mul(a0, b1), Bls.mul(a1, b0)), ri) };
                },
                .arith384_mont => {
                    const m: u384 = @intCast(in[2]);
                    if (m & 1 == 0) return error.CurveDomain;
                    if (m == 1) {
                        w.out = .{0};
                    } else {
                        const ab: u384 = @intCast(@as(u768, @intCast(in[0])) * @as(u768, @intCast(in[1])) % m);
                        const r_mod: u384 = @intCast((@as(u768, 1) << 384) % m);
                        w.out = .{@as(u384, @intCast(@as(u768, ab) * invMod(u384, r_mod, m) % m))};
                    }
                },
                .bls12_381_g1_add, .bls12_381_g1_double => {
                    const ri = blsRInv();
                    var plain: [4]u384 = undefined;
                    for (0..d.inputs) |i| plain[i] = Bls.mul(@intCast(in[i]), ri);
                    const r = if (op == .bls12_381_g1_add) blk: {
                        if (in[0] == in[2]) return error.CurveDomain;
                        break :blk affineAdd(Bls, u384, plain[0], plain[1], plain[2], plain[3]);
                    } else blk: {
                        if (in[1] == 0) return error.CurveDomain;
                        break :blk affineDouble(Bls, u384, plain[0], plain[1]);
                    };
                    w.out = .{ Bls.mul(r[0], BLS_R), Bls.mul(r[1], BLS_R) };
                    w.wit = .{Bls.mul(r[2], BLS_R)};
                },
            }
            return w;
        }
        /// Packet after one call: outputs overwrite the leading bytes.
        pub fn after(packet: *const Packet) Error!Packet {
            const w = try compute(packet);
            var out = packet.*;
            for (w.out, 0..) |x, j| for (0..d.limbs) |b| {
                out[j * d.limbs + b] = spec.limbOf(x, b);
            };
            return out;
        }

        fn value(packet: *const Packet, w: *const Witness, x: spec.Vec) Big {
            return switch (x) {
                .in => |i| operand(packet, i),
                .out => |j| w.out[j],
                .wit => |i| if (d.witnesses == 0) unreachable else w.wit[i],
            };
        }
        fn put(row: *Row, base: usize, count: usize, x: Big) void {
            for (0..count) |b| row[base + b] = spec.limbOf(x, b);
        }
        fn signedPart(packet: *const Packet, w: *const Witness, comptime r: usize, positive: bool) Big {
            var acc: Big = 0;
            inline for (d.relations[r]) |term| if ((term.coef > 0) == positive) {
                const c: Big = @intCast(@abs(term.coef));
                const a = value(packet, w, term.a);
                acc += if (term.b) |b| c * a * value(packet, w, b) else c * (a << @intCast(8 * @as(usize, term.shift)));
            };
            return acc;
        }

        /// Fills an ACTIVE row (MULT is left zero; the trace sets it).
        pub fn fill(row: *Row, packet: *const Packet) Error!Witness {
            const w = try compute(packet);
            @memset(row, 0);
            row[L.ACTIVE] = 1;
            for (packet, 0..) |b, i| row[L.PACKET + i] = b;
            for (w.out, 0..) |x, j| put(row, L.OUT + j * d.limbs, d.limbs, x);
            for (w.wit, 0..) |x, j| put(row, L.WIT + j * d.limbs, d.limbs, x);
            const m = modulusOf(packet);
            inline for (0..L.RELATIONS) |r| {
                const g = L.GEOMETRY[r];
                const pos = signedPart(packet, &w, r, true) + g.kp;
                const neg = signedPart(packet, &w, r, false);
                std.debug.assert(pos >= neg and (pos - neg) % m == 0);
                const q = (pos - neg) / m;
                std.debug.assert(q >> @intCast(8 * g.q_bytes) == 0);
                put(row, L.QUOTIENT[r], g.q_bytes, q);
                // Signed coefficients exactly as the equations form them.
                var coef: [spec.MAX_COEFFICIENTS + 2]i64 = @splat(0);
                inline for (d.relations[r]) |term| {
                    const a = L.column(term.a);
                    if (term.b) |bv| {
                        const b = L.column(bv);
                        for (0..d.limbs) |i| for (0..d.limbs) |j| {
                            coef[i + j] += @as(i64, term.coef) * row[a + i] * row[b + j];
                        };
                    } else for (0..d.limbs) |i| {
                        coef[term.shift + i] += @as(i64, term.coef) * row[a + i];
                    }
                }
                for (0..g.coefficients) |n| coef[n] += spec.limbOf(g.kp, n);
                for (0..g.q_bytes) |i| for (0..d.limbs) |j| {
                    coef[i + j] -= @as(i64, row[L.QUOTIENT[r] + i]) * spec.limbOf(m, j);
                };
                var carry: i64 = 0;
                const radix: i64 = @as(i64, 1) << @intCast(8 * g.group);
                const half: i64 = @as(i64, 1) << @intCast(g.carry_bits - 1);
                for (0..g.groups) |j| {
                    var sum: i64 = carry;
                    for (0..g.group) |offset| sum += coef[g.group * j + offset] << @intCast(8 * offset);
                    std.debug.assert(@mod(sum, radix) == 0);
                    carry = @divExact(sum, radix);
                    if (j == g.carries) {
                        std.debug.assert(carry == 0);
                        break;
                    }
                    std.debug.assert(carry >= -half and carry < half);
                    const encoded: u64 = @intCast(carry + half);
                    for (0..g.carry_bytes) |b| row[L.CARRY[r] + g.carry_bytes * j + b] = @as(u8, @truncate(encoded >> @intCast(8 * b)));
                }
            }
            for (L.CHECKS, L.D, L.BORROW) |check, dbase, bbase| {
                const x = value(packet, &w, check.x);
                std.debug.assert(x < m);
                put(row, dbase, d.limbs, m - 1 - x);
                var c: u32 = 0;
                for (0..L.CHUNKS - 1) |i| {
                    const xi = row[L.column(check.x) + 2 * i] + 256 * row[L.column(check.x) + 2 * i + 1];
                    const di = row[dbase + 2 * i] + 256 * row[dbase + 2 * i + 1];
                    const mi: u32 = @intCast((m >> @intCast(16 * i)) & 0xffff);
                    const total = xi + di + c + @intFromBool(i == 0);
                    std.debug.assert(total == mi or total == mi + 65536);
                    c = @intFromBool(total != mi);
                    row[bbase + i] = c;
                }
            }
            if (d.nonzero) |nz| {
                for (0..L.CHUNKS) |i| {
                    const ca: i64 = @intCast((value(packet, &w, nz.a) >> @intCast(16 * i)) & 0xffff);
                    const cb: i64 = if (nz.b) |b| @intCast((value(packet, &w, b) >> @intCast(16 * i)) & 0xffff) else 0;
                    if (ca != cb) {
                        row[L.SEL + i] = 1;
                        const delta = M31.fromU64(@intCast(@mod(ca - cb, @as(i64, core.fields.m31.Modulus))));
                        row[L.INV] = (delta.inv() catch unreachable).v;
                        break;
                    }
                } else unreachable;
            }
            if (d.odd_modulus) row[L.HALF] = @intCast((m & 0xff) >> 1);
            return w;
        }
        /// Payload of Wire35 `wire` (input coordinate, or coords + written coordinate).
        pub fn wireBytes(before: *const Packet, after_packet: *const Packet, wire: usize) [32]u8 {
            return if (wire < L.COORDS) before[32 * wire ..][0..32].* else after_packet[32 * (wire - L.COORDS) ..][0..32].*;
        }
    };
}
