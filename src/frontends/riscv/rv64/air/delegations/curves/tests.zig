//! Constraint-level authority tests for the curve/field truth AIRs. The
//! reference is an independent std.math.big oracle (Fermat inverses, plain
//! big-integer reduction), plus self-certifying group-law checks.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const spec = @import("spec.zig");
const Base = @import("layout.zig");
const NativeOf = @import("native.zig").Native;
const EqOf = @import("equations.zig");
const TraceOf = @import("trace.zig");
const Candidate = @import("../../../ethereum_services/candidate_curves.zig");
const Managed = std.math.big.int.Managed;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Big = spec.Big;
const Op = spec.Op;
const MODULUS = core.fields.m31.Modulus;

pub fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
pub fn qi(v: i64) Q {
    return Q.fromBase(M.fromU64(@intCast(@mod(v, MODULUS))));
}

// ------------------------------------------------------------ oracle

const Z = struct {
    a: std.mem.Allocator,
    fn from(self: Z, x: anytype) !Managed {
        return Managed.initSet(self.a, x);
    }
    fn mod(self: Z, x: *const Managed, m: *const Managed) !Managed {
        var quo = try Managed.init(self.a);
        defer quo.deinit();
        var rem = try Managed.init(self.a);
        try quo.divFloor(&rem, x, m);
        return rem;
    }
    fn mulMod(self: Z, x: *const Managed, y: *const Managed, m: *const Managed) !Managed {
        var p = try Managed.init(self.a);
        defer p.deinit();
        try p.mul(x, y);
        return self.mod(&p, m);
    }
    fn powMod(self: Z, base: *const Managed, exp: Big, m: *const Managed) !Managed {
        var result = try self.from(1);
        var b = try self.mod(base, m);
        defer b.deinit();
        var e = exp;
        while (e != 0) : (e >>= 1) {
            if (e & 1 == 1) {
                const next = try self.mulMod(&result, &b, m);
                result.deinit();
                result = next;
            }
            const sq = try self.mulMod(&b, &b, m);
            b.deinit();
            b = sq;
        }
        return result;
    }
    fn toBig(_: Z, x: *const Managed) !Big {
        return x.toInt(Big);
    }
};

/// Independent reference: plain definitions over std.math.big. Null when a
/// precondition fails.
fn oracle(comptime op: Op, a: std.mem.Allocator, packet: []const u8) !?[spec.def(op).outputs]Big {
    const d = comptime spec.def(op);
    const z = Z{ .a = a };
    var vals: [d.inputs]Managed = undefined;
    var made: usize = 0;
    defer for (vals[0..made]) |*v| v.deinit();
    for (&vals, 0..) |*v, i| {
        var x: Big = 0;
        for (0..d.limbs) |b| x |= @as(Big, packet[i * d.limbs + b]) << @intCast(8 * b);
        v.* = try z.from(x);
        made += 1;
    }
    var out: [d.outputs]Big = undefined;
    switch (d.modulus) {
        .variable => {
            // arith384_mont: r = a b (2^-1)^384 mod m, 2^-1 = (m + 1) / 2.
            const m_big = try z.toBig(&vals[2]);
            if (m_big & 1 == 0) return null;
            var m = try z.from(m_big);
            defer m.deinit();
            var half = try z.from((m_big + 1) / 2);
            defer half.deinit();
            var rinv = try z.powMod(&half, 384, &m);
            defer rinv.deinit();
            var ab = try z.mulMod(&vals[0], &vals[1], &m);
            defer ab.deinit();
            var r = try z.mulMod(&ab, &rinv, &m);
            defer r.deinit();
            out[0] = try z.toBig(&r);
            return out;
        },
        .constant => |pv| {
            var p = try z.from(pv);
            defer p.deinit();
            for (d.canonical_inputs) |i| if ((try z.toBig(&vals[i])) >= pv) return null;
            const montgomery = d.limbs == 48;
            var r_mod = try z.from((@as(Big, 1) << 384) % pv);
            defer r_mod.deinit();
            var rinv = try z.powMod(&r_mod, pv - 2, &p);
            defer rinv.deinit();
            // Plain values of the inputs.
            var plain: [d.inputs]Managed = undefined;
            var plain_made: usize = 0;
            defer for (plain[0..plain_made]) |*v| v.deinit();
            const curve = d.witnesses == 1;
            for (&plain, &vals) |*dst, *src| {
                dst.* = if (montgomery and curve) try z.mulMod(src, &rinv, &p) else try z.mod(src, &p);
                plain_made += 1;
            }
            var results: [2]Managed = undefined;
            var results_made: usize = 0;
            defer for (results[0..results_made]) |*v| v.deinit();
            if (!curve) {
                var t1 = try z.mulMod(&plain[0], &plain[2], &p);
                defer t1.deinit();
                var t2 = try z.mulMod(&plain[1], &plain[3], &p);
                defer t2.deinit();
                var t3 = try z.mulMod(&plain[0], &plain[3], &p);
                defer t3.deinit();
                var t4 = try z.mulMod(&plain[1], &plain[2], &p);
                defer t4.deinit();
                var c0 = try Managed.init(a);
                defer c0.deinit();
                try c0.sub(&t1, &t2);
                var c1 = try Managed.init(a);
                defer c1.deinit();
                try c1.add(&t3, &t4);
                results[0] = if (montgomery) try z.mulMod(&c0, &rinv, &p) else try z.mod(&c0, &p);
                results_made += 1;
                results[1] = if (montgomery) try z.mulMod(&c1, &rinv, &p) else try z.mod(&c1, &p);
                results_made += 1;
            } else {
                const add = d.inputs == 4;
                var num = try Managed.init(a);
                defer num.deinit();
                var den = try Managed.init(a);
                defer den.deinit();
                if (add) {
                    if ((try z.toBig(&vals[0])) == (try z.toBig(&vals[2]))) return null;
                    try num.sub(&plain[3], &plain[1]);
                    try den.sub(&plain[2], &plain[0]);
                } else {
                    if ((try z.toBig(&vals[1])) == 0) return null;
                    var xx = try z.mulMod(&plain[0], &plain[0], &p);
                    defer xx.deinit();
                    var three = try z.from(3);
                    defer three.deinit();
                    try num.mul(&xx, &three);
                    try den.add(&plain[1], &plain[1]);
                }
                var den_mod = try z.mod(&den, &p);
                defer den_mod.deinit();
                var den_inv = try z.powMod(&den_mod, pv - 2, &p);
                defer den_inv.deinit();
                var l = try z.mulMod(&num, &den_inv, &p);
                defer l.deinit();
                var x3 = try z.mulMod(&l, &l, &p);
                defer x3.deinit();
                try x3.sub(&x3, &plain[0]);
                try x3.sub(&x3, if (add) &plain[2] else &plain[0]);
                var x3m = try z.mod(&x3, &p);
                defer x3m.deinit();
                var diff = try Managed.init(a);
                defer diff.deinit();
                try diff.sub(&plain[0], &x3m);
                var y3 = try z.mulMod(&l, &diff, &p);
                defer y3.deinit();
                try y3.sub(&y3, &plain[1]);
                results[0] = if (montgomery) try z.mulMod(&x3m, &r_mod, &p) else try z.mod(&x3m, &p);
                results_made += 1;
                results[1] = if (montgomery) try z.mulMod(&y3, &r_mod, &p) else try z.mod(&y3, &p);
                results_made += 1;
            }
            for (&out, results[0..d.outputs]) |*o, *r| o.* = try z.toBig(r);
            return out;
        },
    }
}

// ------------------------------------------------------------ harness

pub fn Harness(comptime op: anytype) type {
    if (@TypeOf(op) == @TypeOf(.enum_literal)) return Harness(@as(Op, op));
    return struct {
        pub const N = NativeOf(op);
        pub const L = N.L;
        pub const d = L.DEF;
        pub const Eq = EqOf.Equations(op);
        pub const View = struct {
            fixed_values: [Base.FIXED]Q,
            main_values: []const Q,
            previous_active: Q,
            inter: []const Q = &.{},
            previous_inter: []const Q = &.{},
            pub fn fixed(self: *const View, c: usize) Q {
                return self.fixed_values[c];
            }
            pub fn main(self: *const View, c: usize) Q {
                return self.main_values[c];
            }
            pub fn previousActive(self: *const View) Q {
                return self.previous_active;
            }
            pub fn interaction(self: *const View, c: usize) Q {
                return self.inter[c];
            }
            pub fn previousInteraction(self: *const View, c: usize) Q {
                return self.previous_inter[c];
            }
        };
        pub fn rowOf(packet: *const N.Packet, main: *[L.MAIN]Q) !N.Witness {
            var row: N.Row = undefined;
            const w = try N.fill(&row, packet);
            for (main, row) |*dst, v| dst.* = q(v);
            return w;
        }
        /// First nonzero MAIN residual (activity uses calls = 1000, row 0).
        pub fn firstFailure(main: []const Q) ?usize {
            const view = View{ .fixed_values = .{ q(0), q(1), q(0), q(0) }, .main_values = main, .previous_active = q(0) };
            var values: [L.MAIN_CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &values };
            Eq.emitMain(Q, &view, .{ .calls = 1000, .first_id = 1 }, &sink);
            std.debug.assert(sink.count == L.MAIN_CONSTRAINTS);
            for (values, 0..) |v, i| if (!v.isZero()) return i;
            return null;
        }
        pub fn outOfRangeQuery(main: []const Q) bool {
            const view = View{ .fixed_values = .{ q(0), q(1), q(0), q(0) }, .main_values = main, .previous_active = q(0) };
            for (0..L.BYTE_QUERIES) |i| {
                const v = Eq.byteQuery(Q, &view, i).tryIntoM31() catch return true;
                if (v.v > 255) return true;
            }
            return false;
        }
        /// Accepted by MAIN residuals and every BYTE query in range.
        pub fn accepted(main: []const Q) bool {
            return firstFailure(main) == null and !outOfRangeQuery(main);
        }
        pub fn packetOf(values: []const Big) N.Packet {
            var p: N.Packet = @splat(0);
            for (values, 0..) |v, i| for (0..d.limbs) |b| {
                p[i * d.limbs + b] = spec.limbOf(v, b);
            };
            return p;
        }
        pub fn bytesOf(x: Big) [d.limbs]i64 {
            var out: [d.limbs]i64 = undefined;
            for (&out, 0..) |*b, i| b.* = spec.limbOf(x, i);
            return out;
        }
        /// A cheating prover's row: arbitrary (possibly out-of-range) output
        /// and witness limbs, with q, carries, D and borrows recomputed as a
        /// prover would (floor divisions, never asserting a range).
        pub fn forge(packet: *const N.Packet, outs: []const [d.limbs]i64, wits: []const [d.limbs]i64, main: *[L.MAIN]Q) void {
            var vals = forgeValues(packet, outs, wits);
            inline for (0..L.RELATIONS) |r| setQuotient(r, &vals);
            deriveCarriesAndChecks(&vals);
            for (main, vals) |*dst, v| dst.* = qi(v);
        }
        const SB = i2048;
        pub fn toSigned(v: []const i64, base: usize, n: usize) SB {
            var x: SB = 0;
            var i = n;
            while (i > 0) {
                i -= 1;
                x = x * 256 + v[base + i];
            }
            return x;
        }
        pub fn modulusOf(vals: *const [L.MAIN]i64) SB {
            return switch (d.modulus) {
                .constant => |p| @intCast(p),
                .variable => |m| toSigned(vals, L.column(.{ .in = m }), d.limbs),
            };
        }
        /// The honest row with the packet, outputs and witnesses replaced
        /// (signed integers; nothing re-derived yet).
        pub fn forgeValues(packet: *const N.Packet, outs: []const [d.limbs]i64, wits: []const [d.limbs]i64) [L.MAIN]i64 {
            var row: N.Row = undefined;
            _ = N.fill(&row, packet) catch @memset(&row, 0);
            row[L.ACTIVE] = 1;
            for (packet, 0..) |b, i| row[L.PACKET + i] = b;
            var vals: [L.MAIN]i64 = undefined;
            for (&vals, row) |*dst, v| dst.* = v;
            for (outs, 0..) |o, j| for (o, 0..) |b, i| {
                vals[L.OUT + j * d.limbs + i] = b;
            };
            for (wits, 0..) |o, j| for (o, 0..) |b, i| {
                vals[L.WIT + j * d.limbs + i] = b;
            };
            return vals;
        }
        /// Floor quotient of relation r into its q limbs (the top limb takes
        /// any overflow, so it may leave the byte range).
        pub fn setQuotient(comptime r: usize, vals: *[L.MAIN]i64) void {
            const g = L.GEOMETRY[r];
            var sum: SB = @intCast(g.kp);
            inline for (d.relations[r]) |term| {
                const a = toSigned(vals, L.column(term.a), d.limbs);
                sum += if (term.b) |b| term.coef * a * toSigned(vals, L.column(b), d.limbs) else term.coef * a * (@as(SB, 1) << @intCast(8 * @as(usize, term.shift)));
            }
            var qv = @divFloor(sum, modulusOf(vals));
            for (0..g.q_bytes) |i| {
                vals[L.QUOTIENT[r] + i] = @intCast(@mod(qv, 256));
                qv = @divFloor(qv, 256);
            }
            vals[L.QUOTIENT[r] + g.q_bytes - 1] += @intCast(qv * 256);
        }
        /// Carries, D bytes and borrows re-derived from the current (possibly
        /// tampered, possibly out-of-range) limbs exactly as a prover would:
        /// floor divisions, never asserting a range.
        pub fn deriveCarriesAndChecks(vals: *[L.MAIN]i64) void {
            inline for (0..L.RELATIONS) |r| {
                const g = L.GEOMETRY[r];
                var coef: [spec.MAX_COEFFICIENTS + 2]i64 = @splat(0);
                inline for (d.relations[r]) |term| {
                    const a = L.column(term.a);
                    if (term.b) |bv| {
                        const b = L.column(bv);
                        for (0..d.limbs) |i| for (0..d.limbs) |j| {
                            coef[i + j] += @as(i64, term.coef) * vals[a + i] * vals[b + j];
                        };
                    } else for (0..d.limbs) |i| {
                        coef[term.shift + i] += @as(i64, term.coef) * vals[a + i];
                    }
                }
                for (0..g.coefficients) |n| coef[n] += spec.limbOf(g.kp, n);
                for (0..g.q_bytes) |i| for (0..d.limbs) |j| {
                    const mj: i64 = switch (d.modulus) {
                        .constant => |p| spec.limbOf(p, j),
                        .variable => |m| vals[L.column(.{ .in = m }) + j],
                    };
                    coef[i + j] -= vals[L.QUOTIENT[r] + i] * mj;
                };
                var carry: i64 = 0;
                const radix: i64 = @as(i64, 1) << @intCast(8 * g.group);
                const half: i64 = @as(i64, 1) << @intCast(g.carry_bits - 1);
                for (0..g.carries) |j| {
                    var s: i64 = carry;
                    for (0..g.group) |offset| s += coef[g.group * j + offset] << @intCast(8 * offset);
                    carry = @divFloor(s, radix);
                    var e = carry + half;
                    for (0..g.carry_bytes) |b| {
                        vals[L.CARRY[r] + g.carry_bytes * j + b] = if (b + 1 == g.carry_bytes) e else @mod(e, 256);
                        e = @divFloor(e, 256);
                    }
                }
            }
            for (L.CHECKS, L.D, L.BORROW) |check, dbase, bbase| {
                var c: i64 = 0;
                for (0..L.CHUNKS) |i| {
                    const xc = L.column(check.x);
                    const xi = vals[xc + 2 * i] + 256 * vals[xc + 2 * i + 1];
                    const mi: i64 = switch (d.modulus) {
                        .constant => |p| @intCast((p >> @intCast(16 * i)) & 0xffff),
                        .variable => |m| vals[L.column(.{ .in = m }) + 2 * i] + 256 * vals[L.column(.{ .in = m }) + 2 * i + 1],
                    };
                    var di = mi - xi - c - @as(i64, @intFromBool(i == 0));
                    c = 0;
                    if (i + 1 < L.CHUNKS and di < 0) {
                        di += 65536;
                        c = 1;
                    }
                    vals[dbase + 2 * i] = @mod(di, 256);
                    vals[dbase + 2 * i + 1] = @divFloor(di, 256);
                    if (i + 1 < L.CHUNKS) vals[bbase + i] = c;
                }
            }
        }
        pub fn randomBelow(rng: std.Random, bound: Big) Big {
            var x: Big = 0;
            for (0..d.limbs / 8) |i| x |= @as(Big, rng.int(u64)) << @intCast(64 * i);
            return switch (rng.uintLessThan(u8, 8)) {
                0 => 0,
                1 => 1,
                2 => bound - 1,
                3 => bound - 1 - rng.int(u16),
                4 => rng.int(u64),
                else => x % bound,
            };
        }
        /// A random packet satisfying the preconditions.
        pub fn randomPacket(rng: std.Random) N.Packet {
            const full: Big = (@as(Big, 1) << @intCast(8 * d.limbs)) - 1;
            while (true) {
                var vals: [d.inputs]Big = undefined;
                for (&vals, 0..) |*v, i| {
                    const canonical = std.mem.indexOfScalar(u8, d.canonical_inputs, @intCast(i)) != null;
                    v.* = switch (d.modulus) {
                        .constant => |p| if (canonical) randomBelow(rng, p) else randomBelow(rng, full),
                        .variable => randomBelow(rng, full),
                    };
                }
                if (d.odd_modulus) {
                    const m = &vals[d.modulus.variable];
                    m.* = switch (rng.uintLessThan(u8, 6)) {
                        0 => 1,
                        1 => 3,
                        2 => spec.BLS12_381_P,
                        3 => rng.int(u64) | 1,
                        else => m.* | 1,
                    };
                }
                var p = packetOf(&vals);
                for (d.inputs * d.limbs..L.PACKET_BYTES) |i| p[i] = rng.int(u8);
                _ = N.compute(&p) catch continue;
                return p;
            }
        }
    };
}

// ------------------------------------------------------------ tests

/// Every truth key of the generic authority: the seven curve/field ops and
/// the secp256k1 RCB row truths (Wire35 kinds 1/2).
pub const KEYS = .{ Op.bn254_g1_add, Op.bn254_g1_double, Op.bn254_fp2_mul, Op.bls12_381_fp2_mul, Op.arith384_mont, Op.bls12_381_g1_add, Op.bls12_381_g1_double, spec.SecpKind.add, spec.SecpKind.double };
comptime {
    if (KEYS.len != spec.ALL.len + 2) @compileError("curve test key roster drift");
}

test "geometry: exact carry certificates, widths and degree budget" {
    inline for (KEYS) |op| {
        const L = Base.Layout(op);
        inline for (L.GEOMETRY) |g| {
            const radix: u64 = @as(u64, 1) << @intCast(8 * g.group);
            try std.testing.expect(g.group_bound + (@as(u64, 1) << @intCast(g.carry_bits - 1)) * (radix + 1) < MODULUS);
            try std.testing.expect(g.honest_carry < (@as(u64, 1) << @intCast(g.carry_bits - 1)));
        }
        try std.testing.expect(L.QUERIES.len == L.BYTE_QUERIES);
        try std.testing.expect(L.MAIN < 4096 and L.CONSTRAINTS > L.MAIN_CONSTRAINTS);
        std.debug.print("{s}: main {d} interaction {d} cells/row {d} constraints {d} byte queries {d}\n", .{ @tagName(op), L.MAIN, L.INTERACTION, L.MAIN + L.INTERACTION, L.CONSTRAINTS, L.BYTE_QUERIES });
    }
}

test "known answers: every op agrees with the independent big-integer oracle and the candidate executor" {
    const a = std.testing.allocator;
    inline for (spec.ALL) |op| {
        const H = Harness(op);
        var prng = std.Random.DefaultPrng.init(0xc0ffee + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        for (0..60) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.rowOf(&packet, &main);
            const expected = (try oracle(op, a, &packet)) orelse return error.OracleRejectedValidPacket;
            for (w.out, expected) |x, y| try std.testing.expectEqual(y, x);
            try std.testing.expect(H.accepted(&main));
        }
    }
}

const BN_ORDER: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
const BLS_ORDER: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
const BLS_GX: u384 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
const BLS_GY: u384 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

/// [k] P by double-and-add through the service rows (every row checked).
fn scalarMul(comptime add_op: Op, comptime dbl_op: Op, point: [2]Big, k: u256) ![2]Big {
    const HA = Harness(add_op);
    const HD = Harness(dbl_op);
    var main_a: [HA.L.MAIN]Q = undefined;
    var main_d: [HD.L.MAIN]Q = undefined;
    var acc: ?[2]Big = null;
    var bit: usize = 256;
    while (bit > 0) {
        bit -= 1;
        if (acc) |p| {
            const w = try HD.rowOf(&HD.packetOf(&p), &main_d);
            try std.testing.expect(HD.accepted(&main_d));
            acc = w.out;
        }
        if ((k >> @intCast(bit)) & 1 == 1) {
            if (acc) |p| {
                const w = try HA.rowOf(&HA.packetOf(&.{ p[0], p[1], point[0], point[1] }), &main_a);
                try std.testing.expect(HA.accepted(&main_a));
                acc = w.out;
            } else acc = point;
        }
    }
    return acc.?;
}

test "group law: BN254 [r-1]G = -G and BLS12-381 [r-1]G = -G (Montgomery) through accepted rows" {
    const bn_p = spec.BN254_P;
    const minus = try scalarMul(.bn254_g1_add, .bn254_g1_double, .{ 1, 2 }, BN_ORDER - 1);
    try std.testing.expectEqual(@as(Big, 1), minus[0]);
    try std.testing.expectEqual(@as(Big, bn_p - 2), minus[1]);
    // 2G and 3G lie on y^2 = x^3 + 3.
    for ([_]u256{ 2, 3, 5 }) |k| {
        const p = try scalarMul(.bn254_g1_add, .bn254_g1_double, .{ 1, 2 }, k);
        const x: u256 = @intCast(p[0]);
        const y: u256 = @intCast(p[1]);
        const Bn = @import("native.zig").Bn;
        try std.testing.expectEqual(Bn.mul(y, y), Bn.add(Bn.mul(Bn.mul(x, x), x), 3));
    }
    const Bls = @import("native.zig").Bls;
    const R = @import("native.zig").BLS_R;
    const RI = @import("native.zig").BLS_R_INV;
    try std.testing.expectEqual(Bls.mul(BLS_GY, BLS_GY), Bls.add(Bls.mul(Bls.mul(BLS_GX, BLS_GX), BLS_GX), 4));
    const g = [2]Big{ Bls.mul(BLS_GX, R), Bls.mul(BLS_GY, R) };
    const neg = try scalarMul(.bls12_381_g1_add, .bls12_381_g1_double, g, BLS_ORDER - 1);
    try std.testing.expectEqual(@as(Big, BLS_GX), Bls.mul(@intCast(neg[0]), RI));
    try std.testing.expectEqual(@as(Big, spec.BLS12_381_P - BLS_GY), Bls.mul(@intCast(neg[1]), RI));
    // 2G and 3G on y^2 = x^3 + 4 (plain form).
    for ([_]u256{ 2, 3 }) |k| {
        const p = try scalarMul(.bls12_381_g1_add, .bls12_381_g1_double, g, k);
        const x = Bls.mul(@intCast(p[0]), RI);
        const y = Bls.mul(@intCast(p[1]), RI);
        try std.testing.expectEqual(Bls.mul(y, y), Bls.add(Bls.mul(Bls.mul(x, x), x), 4));
    }
}

test "candidate executor agreement: native packets equal the execution-only candidate semantics" {
    inline for (spec.ALL) |op| {
        const H = Harness(op);
        const d = H.d;
        var prng = std.Random.DefaultPrng.init(0xca11 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        for (0..40) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.N.compute(&packet);
            var in: [d.inputs]Big = undefined;
            for (&in, 0..) |*x, i| x.* = H.N.operand(&packet, i);
            const C = Candidate;
            const expected: [d.outputs]Big = switch (op) {
                .bn254_g1_add => blk: {
                    const r = C.affineAdd(C.Bn254, u256, @intCast(in[0]), @intCast(in[1]), @intCast(in[2]), @intCast(in[3]));
                    break :blk .{ r[0], r[1] };
                },
                .bn254_g1_double => blk: {
                    const r = C.affineDouble(C.Bn254, u256, @intCast(in[0]), @intCast(in[1]));
                    break :blk .{ r[0], r[1] };
                },
                .bn254_fp2_mul => blk: {
                    const r = C.fp2Mul(C.Bn254, u256, .{ C.Bn254.reduce(@intCast(in[0])), C.Bn254.reduce(@intCast(in[1])) }, .{ C.Bn254.reduce(@intCast(in[2])), C.Bn254.reduce(@intCast(in[3])) });
                    break :blk .{ r[0], r[1] };
                },
                .bls12_381_fp2_mul => blk: {
                    const r = C.fp2Mul(C.Bls, u384, .{ C.Bls.reduce(@intCast(in[0])), C.Bls.reduce(@intCast(in[1])) }, .{ C.Bls.reduce(@intCast(in[2])), C.Bls.reduce(@intCast(in[3])) });
                    const ri = C.Bls.inv(@import("native.zig").BLS_R);
                    break :blk .{ C.Bls.mul(r[0], ri), C.Bls.mul(r[1], ri) };
                },
                .arith384_mont => .{C.mont384(@intCast(in[0]), @intCast(in[1]), @intCast(in[2]))},
                .bls12_381_g1_add, .bls12_381_g1_double => blk: {
                    const ri = C.Bls.inv(@import("native.zig").BLS_R);
                    const R = @import("native.zig").BLS_R;
                    const r = if (op == .bls12_381_g1_add) C.affineAdd(C.Bls, u384, C.Bls.mul(@intCast(in[0]), ri), C.Bls.mul(@intCast(in[1]), ri), C.Bls.mul(@intCast(in[2]), ri), C.Bls.mul(@intCast(in[3]), ri)) else C.affineDouble(C.Bls, u384, C.Bls.mul(@intCast(in[0]), ri), C.Bls.mul(@intCast(in[1]), ri));
                    break :blk .{ C.Bls.mul(r[0], R), C.Bls.mul(r[1], R) };
                },
            };
            for (w.out, expected) |x, y| try std.testing.expectEqual(y, x);
        }
    }
}

test "adversarial: wrong outputs, non-canonical outputs and wrong slopes are rejected" {
    inline for (KEYS) |op| {
        const H = Harness(op);
        const d = H.d;
        var prng = std.Random.DefaultPrng.init(0xbad + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        var non_canonical: usize = 0;
        for (0..24) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.N.compute(&packet);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            var wits: [d.witnesses][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            for (&wits, w.wit) |*o, x| o.* = H.bytesOf(x);
            // The forger reproduces the honest row.
            H.forge(&packet, &outs, &wits, &main);
            try std.testing.expect(H.accepted(&main));
            // Wrong output: any other value fails a relation or a range.
            const j = rng.uintLessThan(usize, d.outputs);
            var bad = outs;
            bad[j] = H.bytesOf(w.out[j] ^ (@as(Big, 1) << rng.uintLessThan(u9, @intCast(8 * d.limbs - 8))));
            H.forge(&packet, &bad, &wits, &main);
            try std.testing.expect(!H.accepted(&main));
            // Non-canonical output (x + M, same residue): relations hold, the
            // canonical check rejects.
            const m: Big = switch (d.modulus) {
                .constant => |p| p,
                .variable => |mi| H.N.operand(&packet, mi),
            };
            if (w.out[j] + m < (@as(Big, 1) << @intCast(8 * d.limbs))) {
                var alias = outs;
                alias[j] = H.bytesOf(w.out[j] + m);
                H.forge(&packet, &alias, &wits, &main);
                try std.testing.expect(!H.accepted(&main));
                non_canonical += 1;
            }
            // Wrong slope.
            if (d.witnesses == 1) {
                var slope = wits;
                slope[0] = H.bytesOf((w.wit[0] + 1) % d.modulus.constant);
                H.forge(&packet, &outs, &slope, &main);
                try std.testing.expect(!H.accepted(&main));
            }
        }
        // secp outputs are almost never below 2^256 - p; the aliases are
        // exercised on crafted zero outputs in secp_tests.zig.
        if (comptime @TypeOf(op) == Op) try std.testing.expect(non_canonical > 0);
    }
}

test "adversarial: equal x (add) and y = 0 (double) admit no nonzero proof; non-canonical inputs fail" {
    inline for (.{ Op.bn254_g1_add, Op.bn254_g1_double, Op.bls12_381_g1_add, Op.bls12_381_g1_double }) |op| {
        const H = Harness(op);
        const d = H.d;
        const p = d.modulus.constant;
        var prng = std.Random.DefaultPrng.init(0xe0 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        for (0..16) |_| {
            var vals: [d.inputs]Big = undefined;
            for (&vals) |*v| v.* = H.randomBelow(rng, p);
            if (d.inputs == 4) vals[2] = vals[0] else vals[1] = 0;
            const packet = H.packetOf(&vals);
            try std.testing.expectError(error.CurveDomain, H.N.compute(&packet));
            // Any slope, consistent outputs; every one-hot choice fails.
            const l = H.randomBelow(rng, p);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            outs[0] = H.bytesOf(rng.int(u64));
            outs[1] = H.bytesOf(rng.int(u64));
            const wits = [_][d.limbs]i64{H.bytesOf(l)};
            H.forge(&packet, &outs, &wits, &main);
            for (0..H.L.CHUNKS) |i| {
                for (0..H.L.CHUNKS) |k| main[H.L.SEL + k] = q(@intFromBool(k == i));
                main[H.L.INV] = qi(rng.int(u31));
                try std.testing.expect(H.firstFailure(&main) != null);
            }
        }
        // Non-canonical input x + p with the honest residue: rejected.
        for (0..8) |_| {
            const packet = H.randomPacket(rng);
            var vals: [d.inputs]Big = undefined;
            for (&vals, 0..) |*v, i| v.* = H.N.operand(&packet, i);
            const i = rng.uintLessThan(usize, d.inputs);
            if (vals[i] + p >= (@as(Big, 1) << @intCast(8 * d.limbs))) continue;
            vals[i] += p;
            const bad = H.packetOf(&vals);
            try std.testing.expectError(error.CurveDomain, H.N.compute(&bad));
            const w = try H.N.compute(&packet);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            const wits = [_][d.limbs]i64{H.bytesOf(w.wit[0])};
            H.forge(&bad, &outs, &wits, &main);
            try std.testing.expect(!H.accepted(&main));
        }
    }
}

test "adversarial: arith384_mont even modulus, r >= m and non-canonical quotient limbs" {
    const H = Harness(.arith384_mont);
    var prng = std.Random.DefaultPrng.init(0x384);
    const rng = prng.random();
    var main: [H.L.MAIN]Q = undefined;
    var exercised: [3]usize = @splat(0);
    for (0..32) |_| {
        var packet = H.randomPacket(rng);
        const w = try H.N.compute(&packet);
        const m = H.N.operand(&packet, 2);
        // r + m (same residue) when it fits: the r < m check rejects.
        if (w.out[0] + m < (@as(Big, 1) << 384)) {
            H.forge(&packet, &.{H.bytesOf(w.out[0] + m)}, &.{}, &main);
            try std.testing.expect(!H.accepted(&main));
            exercised[0] += 1;
        }
        // Even modulus: honest compute traps; any row fails the odd check.
        packet[2 * 48] &= 0xfe;
        if (H.N.operand(&packet, 2) != 0) {
            try std.testing.expectError(error.CurveDomain, H.N.compute(&packet));
            H.forge(&packet, &.{H.bytesOf(0)}, &.{}, &main);
            for (0..256) |h| {
                main[H.L.HALF] = q(@intCast(h));
                try std.testing.expect(!H.accepted(&main));
            }
            exercised[1] += 1;
        }
    }
    // Non-canonical q limbs: q_i + 256, q_{i+1} - 1 keeps the integer q. A
    // cheating prover re-derives the carries for the shifted limbs (the
    // per-group sums change even though q does not), so every MAIN residual
    // holds and ONLY the BYTE range check of q_i rejects.
    for (0..16) |_| {
        const packet = H.randomPacket(rng);
        const w = try H.N.compute(&packet);
        var vals = H.forgeValues(&packet, &.{H.bytesOf(w.out[0])}, &.{});
        H.setQuotient(0, &vals);
        H.deriveCarriesAndChecks(&vals);
        for (&main, vals) |*dst, v| dst.* = qi(v);
        try std.testing.expect(H.accepted(&main));
        const base = H.L.QUOTIENT[0];
        const i = rng.uintLessThan(usize, H.L.GEOMETRY[0].q_bytes - 1);
        if (vals[base + i + 1] == 0) continue;
        vals[base + i] += 256;
        vals[base + i + 1] -= 1;
        H.deriveCarriesAndChecks(&vals);
        for (&main, vals) |*dst, v| dst.* = qi(v);
        try std.testing.expectEqual(@as(?usize, null), H.firstFailure(&main));
        try std.testing.expect(H.outOfRangeQuery(&main));
        exercised[2] += 1;
    }
    for (exercised) |e| try std.testing.expect(e > 0);
}

test "every single-cell perturbation of an honest row violates a MAIN residual or a lookup" {
    inline for (KEYS) |op| {
        const H = Harness(op);
        var prng = std.Random.DefaultPrng.init(0xce11 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var packet = H.randomPacket(rng);
        // Nonzero operands so every input byte reaches a product.
        while (true) : (packet = H.randomPacket(rng)) {
            var all = true;
            for (0..H.d.inputs) |i| all = all and H.N.operand(&packet, i) > (@as(Big, 1) << @intCast(8 * H.d.limbs - 16));
            if (all) break;
        }
        var main: [H.L.MAIN]Q = undefined;
        _ = try H.rowOf(&packet, &main);
        try std.testing.expect(H.accepted(&main));
        for (0..H.L.MAIN) |c| {
            const saved = main[c];
            main[c] = main[c].add(q(1));
            defer main[c] = saved;
            // Packet bytes beyond the inputs are bound only by Wire35; MULT
            // only by the BYTE chain.
            const unbound = (c >= H.L.PACKET + H.d.inputs * H.d.limbs and c < H.L.OUT) or c == H.L.MULT;
            if (unbound) {
                try std.testing.expect(H.accepted(&main));
                continue;
            }
            if (H.accepted(&main)) {
                std.debug.print("{s}: perturbing column {d} accepted\n", .{ @tagName(op), c });
                return error.UnboundColumn;
            }
        }
    }
}

test "activity prefix: exactly rows 0..calls-1 may be active" {
    const H = Harness(.bn254_fp2_mul);
    var prng = std.Random.DefaultPrng.init(7);
    const packet = H.randomPacket(prng.random());
    var main: [H.L.MAIN]Q = undefined;
    _ = try H.rowOf(&packet, &main);
    const Eq = H.Eq;
    const check = struct {
        fn f(m: []const Q, fixed: [4]Q, previous: Q) bool {
            const view = H.View{ .fixed_values = fixed, .main_values = m, .previous_active = previous };
            var values: [H.L.MAIN_CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &values };
            Eq.emitMain(Q, &view, .{ .calls = 1000, .first_id = 1 }, &sink);
            for (values) |v| if (!v.isZero()) return false;
            return true;
        }
    }.f;
    var zero: [H.L.MAIN]Q = @splat(Q.zero());
    _ = &zero;
    try std.testing.expect(!check(&zero, .{ q(0), q(1), q(0), q(0) }, q(0))); // row 0 must be active
    try std.testing.expect(!check(&main, .{ q(5), q(0), q(0), q(5) }, q(0))); // no 0 -> 1
    try std.testing.expect(!check(&zero, .{ q(999), q(0), q(0), q(999 & 255) }, q(1))); // 1 -> 0 only at calls
    try std.testing.expect(check(&zero, .{ q(1000), q(0), q(0), q(1000 & 255) }, q(1)));
    try std.testing.expect(!check(&main, .{ q(4), q(0), q(1), q(4) }, q(1))); // LAST inactive
    try std.testing.expect(check(&main, .{ q(4), q(0), q(0), q(4) }, q(1)));
}

pub fn challenges() EqOf.Challenges {
    var wire: EqOf.Wire = undefined;
    wire.offset = q(0x1234567).add(Q.fromPartialEvals(.{ q(1), q(2), q(3), q(4) }));
    for (&wire.coefficients, 0..) |*c, i| c.* = Q.fromPartialEvals(.{ q(@intCast(i + 9)), q(@intCast(3 * i + 1)), q(77), q(@intCast(i * i + 5)) });
    return .{ .bytes = Q.fromPartialEvals(.{ q(0x51), q(0x7abc), q(0x1010), q(0x3) }), .wire = wire };
}

test "interaction: Wire35 claim equals the native sum and every residual vanishes" {
    const a = std.testing.allocator;
    inline for (KEYS) |op| {
        const H = Harness(op);
        const T = TraceOf.Trace(op);
        const L = H.L;
        var prng = std.Random.DefaultPrng.init(0x1a7e + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var packets: [7]H.N.Packet = undefined;
        for (&packets) |*p| p.* = H.randomPacket(rng);
        var source = try T.Source.init(a, &packets, 11, Base.MIN_LOG);
        defer source.deinit();
        const ch = challenges();
        const claim = try source.generateInteraction(ch);
        var expected = Q.zero();
        for (&packets, 0..) |*p, r| {
            const after = try H.N.after(p);
            for (0..L.WIRE_FRACTIONS) |id| {
                const inv = try ch.wire.denominator(&TraceOf.externalTuple(L.PROGRAM_KIND, 11 + @as(u32, @intCast(r)), L.wireLabel(id), H.N.wireBytes(p, &after, id))).inv();
                expected = if (id >= L.COORDS) expected.add(inv) else expected.sub(inv);
            }
        }
        try std.testing.expect(claim.eql(expected));
        const n = source.size();
        const R = @import("../../memory/closed_ram/mod.zig");
        var main: [L.MAIN]Q = undefined;
        var inter: [L.INTERACTION]Q = undefined;
        var previous_inter: [L.INTERACTION]Q = undefined;
        for (0..n) |r| {
            const p = R.trace.physical(r, Base.MIN_LOG);
            const pp = R.trace.physical((r + n - 1) % n, Base.MIN_LOG);
            for (&main, 0..) |*dst, c| dst.* = Q.fromBase(source.main[c * n + p]);
            for (0..L.INTERACTION) |c| {
                inter[c] = Q.fromBase(source.interaction[c * n + p]);
                previous_inter[c] = Q.fromBase(source.interaction[c * n + pp]);
            }
            var view = H.View{ .fixed_values = undefined, .main_values = &main, .previous_active = Q.fromBase(source.main[L.ACTIVE * n + pp]), .inter = &inter, .previous_inter = &previous_inter };
            for (&view.fixed_values, 0..) |*f, c| f.* = Q.fromBase(source.fixed[c * n + p]);
            var values: [L.CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &values };
            H.Eq.emit(Q, &view, .{ .calls = packets.len, .first_id = 11 }, claim, ch, &sink);
            for (values, 0..) |v, i| if (!v.isZero()) {
                std.debug.print("{s}: row {d} constraint {d}\n", .{ @tagName(op), r, i });
                return error.NonzeroResidual;
            };
        }
        // A shifted BYTE multiplicity breaks the chain's closure to zero.
        var forged = try T.Source.init(a, &packets, 11, Base.MIN_LOG);
        defer forged.deinit();
        forged.counts[3] += 1;
        forged.counts[0] -= 1;
        try std.testing.expectError(error.InvalidCurveByteCounts, forged.generateInteraction(ch));
    }
}

test "packed 16-lane residuals equal scalar residuals and every constraint has degree at most 3" {
    @setEvalBranchQuota(100_000_000);
    inline for (KEYS) |op| {
        const H = Harness(op);
        const L = H.L;
        const TOTAL = Base.FIXED + L.MAIN + 1 + 2 * L.INTERACTION;
        const PackedView = struct {
            values: []const E.PackedBase,
            pub fn fixed(self: *const @This(), c: usize) E.PackedBase {
                return self.values[c];
            }
            pub fn main(self: *const @This(), c: usize) E.PackedBase {
                return self.values[Base.FIXED + c];
            }
            pub fn previousActive(self: *const @This()) E.PackedBase {
                return self.values[Base.FIXED + L.MAIN];
            }
            pub fn interaction(self: *const @This(), c: usize) E.PackedBase {
                return self.values[Base.FIXED + L.MAIN + 1 + c];
            }
            pub fn previousInteraction(self: *const @This(), c: usize) E.PackedBase {
                return self.values[Base.FIXED + L.MAIN + 1 + L.INTERACTION + c];
            }
        };
        const viewFrom = struct {
            fn f(values: []const Q) H.View {
                return .{ .fixed_values = values[0..Base.FIXED].*, .main_values = values[Base.FIXED..][0..L.MAIN], .previous_active = values[Base.FIXED + L.MAIN], .inter = values[Base.FIXED + L.MAIN + 1 ..][0..L.INTERACTION], .previous_inter = values[Base.FIXED + L.MAIN + 1 + L.INTERACTION ..][0..L.INTERACTION] };
            }
        }.f;
        const a = std.testing.allocator;
        const ch = challenges();
        const claim = Q.fromPartialEvals(.{ q(3), q(1), q(4), q(1) });
        const span: E.CallSpanFor(Q) = .{ .calls = 7, .first_id = 2 };
        const base = try a.alloc(E.PackedBase, TOTAL);
        defer a.free(base);
        for (base, 0..) |*v, c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*x, lane| x.* = M.fromCanonical(@intCast((1 + c * 17 + lane * 131) % MODULUS));
            v.* = E.PackedBase.fromLanes(lanes);
        }
        const packed_residuals = try a.alloc(E.PackedSecure, L.CONSTRAINTS);
        defer a.free(packed_residuals);
        var psink = E.PackedSink{ .values = packed_residuals };
        const pv = PackedView{ .values = base };
        H.Eq.emit(E.PackedBase, &pv, span, claim, ch, &psink);
        try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), psink.count);
        const values = try a.alloc(Q, TOTAL);
        defer a.free(values);
        const residuals = try a.alloc(Q, L.CONSTRAINTS);
        defer a.free(residuals);
        for (0..E.LANES) |lane| {
            for (base, values) |v, *x| x.* = Q.fromBase(v.lane(lane));
            const view = viewFrom(values);
            var sink = E.Sink{ .values = residuals };
            H.Eq.emit(Q, &view, span, claim, ch, &sink);
            for (residuals, packed_residuals) |x, y| try std.testing.expect(x.eql(y.lane(lane)));
        }
        // Each residual along a QM31 line: the fourth difference vanishes.
        const rows = try a.alloc(Q, 5 * L.CONSTRAINTS);
        defer a.free(rows);
        for (0..5) |step| {
            for (values, 0..) |*x, c| {
                const intercept = Q.fromU32Unchecked(@intCast(1 + c), 2, 3, 4);
                const slope = Q.fromU32Unchecked(5, @intCast(6 + c), 7, 8);
                x.* = intercept.add(slope.mulM31(M.fromCanonical(@intCast(step))));
            }
            const view = viewFrom(values);
            var sink = E.Sink{ .values = rows[step * L.CONSTRAINTS ..][0..L.CONSTRAINTS] };
            H.Eq.emit(Q, &view, span, claim, ch, &sink);
        }
        var cubic = false;
        for (0..L.CONSTRAINTS) |c| {
            const r = struct {
                fn at(all: []const Q, step: usize, k: usize) Q {
                    return all[step * L.CONSTRAINTS + k];
                }
            }.at;
            const third = r(rows, 3, c).sub(r(rows, 2, c).mulM31(M.fromCanonical(3))).add(r(rows, 1, c).mulM31(M.fromCanonical(3))).sub(r(rows, 0, c));
            cubic = cubic or !third.isZero();
            const fourth = r(rows, 4, c).sub(r(rows, 3, c).mulM31(M.fromCanonical(4))).add(r(rows, 2, c).mulM31(M.fromCanonical(6))).sub(r(rows, 1, c).mulM31(M.fromCanonical(4))).add(r(rows, 0, c));
            try std.testing.expect(fourth.isZero());
        }
        try std.testing.expect(cubic);
    }
}

test "adversarial: carry forgery (field-solved carries for a wrong output) is rejected" {
    // A forger with a wrong output solves every group equation but the last
    // one in M31 (c_j = (G_j + c_{j-1}) / R) and encodes each carry with the
    // excess in its top byte. The exactness certificate says only in-range
    // carries make the group equations integer identities, so either the
    // final group residual or a carry/top-byte range query must fail.
    inline for (KEYS) |op| {
        const H = Harness(op);
        const d = H.d;
        const L = H.L;
        var prng = std.Random.DefaultPrng.init(0xca77 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [L.MAIN]Q = undefined;
        for (0..12) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.N.compute(&packet);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            var wits: [d.witnesses][d.limbs]i64 = undefined;
            for (&wits, w.wit) |*o, x| o.* = H.bytesOf(x);
            const limb = rng.uintLessThan(usize, d.limbs - 1);
            outs[0][limb] ^= 1;
            H.forge(&packet, &outs, &wits, &main);
            const view = H.View{ .fixed_values = .{ q(0), q(1), q(0), q(0) }, .main_values = &main, .previous_active = q(0) };
            inline for (0..L.RELATIONS) |r| {
                const g = L.GEOMETRY[r];
                const radix = q(@intCast(@as(u64, 1) << @intCast(8 * g.group)));
                const radix_inv = try radix.inv();
                const half = q(@intCast(@as(u64, 1) << @intCast(g.carry_bits - 1)));
                var previous = Q.zero();
                for (0..g.carries) |j| {
                    var sum = Q.zero();
                    for (0..g.group) |offset| {
                        const n = g.group * j + offset;
                        if (n < g.coefficients) sum = sum.add(H.Eq.coefficient(Q, &view, r, n).mul(q(@intCast(@as(u64, 1) << @intCast(8 * offset)))));
                    }
                    const c = sum.add(previous).mul(radix_inv);
                    previous = c;
                    var e: u64 = (c.add(half).tryIntoM31() catch unreachable).v;
                    for (0..g.carry_bytes) |b| {
                        main[L.CARRY[r] + g.carry_bytes * j + b] = q(@intCast(if (b + 1 == g.carry_bytes) e else e % 256));
                        e /= 256;
                    }
                }
            }
            try std.testing.expect(!H.accepted(&main));
        }
    }
}

test "edge cases: P = Q and P = -Q reject in add, (0,0) is evaluated as an ordinary point" {
    // The ABI has no point at infinity: the guest handles O, P = Q and
    // P = -Q before calling. (0,0) as an input is just the formula's point;
    // the AIR must accept exactly the executor's result, nothing else.
    inline for (.{ .{ Op.bn254_g1_add, Op.bn254_g1_double }, .{ Op.bls12_381_g1_add, Op.bls12_381_g1_double } }) |pair| {
        const HA = Harness(pair[0]);
        const HD = Harness(pair[1]);
        const p = HA.d.modulus.constant;
        var prng = std.Random.DefaultPrng.init(0x1f + @as(u64, @intFromEnum(pair[0])));
        const rng = prng.random();
        var main_a: [HA.L.MAIN]Q = undefined;
        var main_d: [HD.L.MAIN]Q = undefined;
        for (0..8) |_| {
            const x = HA.randomBelow(rng, p);
            const y = HA.randomBelow(rng, p);
            const neg_y = (p - y) % p;
            // P = Q and P = -Q: equal x, no nonzero proof, executor traps.
            inline for (.{ 0, 1 }) |neg| {
                const packet = HA.packetOf(&.{ x, y, x, if (neg == 1) neg_y else y });
                try std.testing.expectError(error.CurveDomain, HA.N.compute(&packet));
                const outs = [_][HA.d.limbs]i64{ HA.bytesOf(rng.int(u64)), HA.bytesOf(rng.int(u64)) };
                HA.forge(&packet, &outs, &.{HA.bytesOf(HA.randomBelow(rng, p))}, &main_a);
                try std.testing.expect(!HA.accepted(&main_a));
            }
            // (0,0) + Q with x_Q != 0, and 2 (0, y): honest rows accept and
            // equal the oracle; flipping an output bit rejects.
            if (x != 0) {
                const packet = HA.packetOf(&.{ 0, 0, x, y });
                const w = try HA.rowOf(&packet, &main_a);
                try std.testing.expect(HA.accepted(&main_a));
                const expected = (try oracle(pair[0], std.testing.allocator, &packet)).?;
                for (w.out, expected) |got, want| try std.testing.expectEqual(want, got);
                var outs: [2][HA.d.limbs]i64 = .{ HA.bytesOf(w.out[0]), HA.bytesOf(w.out[1]) };
                outs[1][0] ^= 1;
                HA.forge(&packet, &outs, &.{HA.bytesOf(w.wit[0])}, &main_a);
                try std.testing.expect(!HA.accepted(&main_a));
            }
            if (y != 0) {
                const packet = HD.packetOf(&.{ 0, y });
                const w = try HD.rowOf(&packet, &main_d);
                try std.testing.expect(HD.accepted(&main_d));
                const expected = (try oracle(pair[1], std.testing.allocator, &packet)).?;
                for (w.out, expected) |got, want| try std.testing.expectEqual(want, got);
            }
            // Doubling (0,0) and (x,0): y = 0 traps and no row is accepted.
            const zero = HD.packetOf(&.{ x, 0 });
            try std.testing.expectError(error.CurveDomain, HD.N.compute(&zero));
        }
    }
}

test "mismatched op tag: tags map to distinct kinds and a wrong-kind Wire35 sum never cancels the truth claim" {
    const a = std.testing.allocator;
    // Tags: injective, curve-only, and every non-curve tag maps to no op.
    inline for (spec.ALL, 0..) |op, i| {
        try std.testing.expectEqual(@as(?Op, op), spec.opOfTag(spec.tag(op)));
        try std.testing.expectEqual(@as(u32, @intCast(i + 5)), Base.Layout(op).PROGRAM_KIND);
        inline for (spec.ALL, 0..) |other, j| if (i != j) try std.testing.expect(spec.tag(op) != spec.tag(other));
    }
    for ([_]u64{ 0, 0x30000, 0x30001, 0x30002, 0x30003, 0x30010, 0x30020, 0x30103, 0x30113, 0x30120, 0x30122, 0x30130, 0x130100 }) |raw|
        try std.testing.expectEqual(@as(?Op, null), spec.opOfTag(raw));
    // The same packet claimed by the bridge under another op's kind (same
    // coordinate count): the truth claim does not cancel it.
    const pairs = .{ .{ Op.bn254_g1_add, Op.bn254_fp2_mul }, .{ Op.bls12_381_fp2_mul, Op.bls12_381_g1_add } };
    inline for (pairs) |pair| {
        const H = Harness(pair[0]);
        const T = TraceOf.Trace(pair[0]);
        const W = Base.Layout(pair[1]);
        comptime std.debug.assert(W.COORDS == H.L.COORDS);
        var prng = std.Random.DefaultPrng.init(0x7a6);
        var packets: [3]H.N.Packet = undefined;
        for (&packets) |*p| p.* = H.randomPacket(prng.random());
        var source = try T.Source.init(a, &packets, 5, Base.MIN_LOG);
        defer source.deinit();
        const ch = challenges();
        const claim = try source.generateInteraction(ch);
        var wrong = Q.zero();
        for (&packets, 0..) |*p, r| {
            const after = try H.N.after(p);
            for (0..H.L.WIRE_FRACTIONS) |id| {
                const inv = try ch.wire.denominator(&TraceOf.externalTuple(W.PROGRAM_KIND, 5 + @as(u32, @intCast(r)), id, H.N.wireBytes(p, &after, id))).inv();
                wrong = if (id >= H.L.COORDS) wrong.add(inv) else wrong.sub(inv);
            }
        }
        try std.testing.expect(!claim.eql(wrong));
    }
}
