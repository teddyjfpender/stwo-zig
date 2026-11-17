//! Shared fixtures and independent relation oracles for this test owner.
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

pub const Z = struct {
    a: std.mem.Allocator,
    pub fn from(self: Z, x: anytype) !Managed {
        return Managed.initSet(self.a, x);
    }
    pub fn mod(self: Z, x: *const Managed, m: *const Managed) !Managed {
        var quo = try Managed.init(self.a);
        defer quo.deinit();
        var rem = try Managed.init(self.a);
        try quo.divFloor(&rem, x, m);
        return rem;
    }
    pub fn mulMod(self: Z, x: *const Managed, y: *const Managed, m: *const Managed) !Managed {
        var p = try Managed.init(self.a);
        defer p.deinit();
        try p.mul(x, y);
        return self.mod(&p, m);
    }
    pub fn powMod(self: Z, base: *const Managed, exp: Big, m: *const Managed) !Managed {
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
    pub fn toBig(_: Z, x: *const Managed) !Big {
        return x.toInt(Big);
    }
};

/// Independent reference: plain definitions over std.math.big. Null when a
/// precondition fails.
pub fn oracle(comptime op: Op, a: std.mem.Allocator, packet: []const u8) !?[spec.def(op).outputs]Big {
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

pub const BN_ORDER: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
pub const BLS_ORDER: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
pub const BLS_GX: u384 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
pub const BLS_GY: u384 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

/// [k] P by double-and-add through the service rows (every row checked).
pub fn scalarMul(comptime add_op: Op, comptime dbl_op: Op, point: [2]Big, k: u256) ![2]Big {
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

pub fn challenges() EqOf.Challenges {
    var wire: EqOf.Wire = undefined;
    wire.offset = q(0x1234567).add(Q.fromPartialEvals(.{ q(1), q(2), q(3), q(4) }));
    for (&wire.coefficients, 0..) |*c, i| c.* = Q.fromPartialEvals(.{ q(@intCast(i + 9)), q(@intCast(3 * i + 1)), q(77), q(@intCast(i * i + 5)) });
    return .{ .bytes = Q.fromPartialEvals(.{ q(0x51), q(0x7abc), q(0x1010), q(0x3) }), .wire = wire };
}
