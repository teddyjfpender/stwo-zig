//! One degree-3 scalar/packed constraint authority per curve/field operation.
//! `v` is a mask view with fixed(c), main(c), previousActive(),
//! interaction(c) and previousInteraction(c); all lanes share this order.
const std = @import("std");
const E = @import("../../evaluation.zig");
const LayoutOf = @import("layout.zig").Layout;
const Base = @import("layout.zig");
const spec = @import("spec.zig");
pub const WireFor = @import("../secp256k1/equations.zig").WireFor;
pub const Wire = WireFor(E.Q);

/// Local BYTE point (drawn after the truth MAIN root is sealed) and the
/// shared Wire35 challenges.
pub fn ChallengesFor(comptime C: type) type {
    return struct { bytes: C, wire: WireFor(C) };
}
pub const Challenges = ChallengesFor(E.Q);

pub fn Equations(comptime op: anytype) type {
    if (@TypeOf(op) == @TypeOf(.enum_literal)) return Equations(@as(spec.Op, op));
    return struct {
        pub const L = LayoutOf(op);
        const d = L.DEF;

        inline fn k(comptime F: type, value: u32) F {
            return E.qFor(F, value);
        }
        fn vecByte(comptime F: type, v: anytype, x: spec.Vec, i: usize) F {
            return v.main(L.column(x) + i);
        }
        fn chunk(comptime F: type, v: anytype, base: usize, i: usize) F {
            return v.main(base + 2 * i).add(v.main(base + 2 * i + 1).mul(k(F, 256)));
        }
        /// Coefficient n of the product of two L-byte vectors.
        fn convolution(comptime F: type, v: anytype, a: usize, b: usize, n: usize) F {
            var acc = F.zero();
            const lo = if (n + 1 > d.limbs) n + 1 - d.limbs else 0;
            var i = lo;
            while (i < d.limbs and i <= n) : (i += 1) acc = acc.add(v.main(a + i).mul(v.main(b + n - i)));
            return acc;
        }
        fn scaled(comptime F: type, x: F, coef: i32) F {
            if (coef == 1) return x;
            if (coef == -1) return x.neg();
            const m = k(F, @intCast(@abs(coef))).mul(x);
            return if (coef < 0) m.neg() else m;
        }
        /// Signed coefficient n of relation r (degree 2).
        pub fn coefficient(comptime F: type, v: anytype, comptime r: usize, n: usize) F {
            const g = L.GEOMETRY[r];
            var acc = F.zero();
            inline for (d.relations[r]) |term| {
                if (term.b) |b| {
                    if (n < 2 * d.limbs - 1) acc = acc.add(scaled(F, convolution(F, v, L.column(term.a), L.column(b), n), term.coef));
                } else if (n >= term.shift and n < @as(usize, term.shift) + d.limbs) {
                    acc = acc.add(scaled(F, vecByte(F, v, term.a, n - term.shift), term.coef));
                }
            }
            const active = v.main(L.ACTIVE);
            const kp = spec.limbOf(g.kp, n);
            if (kp != 0) acc = acc.add(active.mul(k(F, kp)));
            // - q * M
            const q = L.QUOTIENT[r];
            const lo = if (n + 1 > d.limbs) n + 1 - d.limbs else 0;
            var i = lo;
            var qm = F.zero();
            while (i < g.q_bytes and i <= n) : (i += 1) {
                const j = n - i;
                switch (d.modulus) {
                    .constant => {
                        const limb = L.modulusByte(j);
                        if (limb != 0) qm = qm.add(v.main(q + i).mul(k(F, limb)));
                    },
                    .variable => |m| qm = qm.add(v.main(q + i).mul(vecByte(F, v, .{ .in = m }, j))),
                }
            }
            return acc.sub(qm);
        }
        /// Encoded carry j of relation r: bytes - 2^(bits-1) * active.
        pub fn carry(comptime F: type, v: anytype, comptime r: usize, j: usize) F {
            const g = L.GEOMETRY[r];
            if (j >= g.carries) return F.zero();
            var acc = F.zero();
            const base = L.CARRY[r] + g.carry_bytes * j;
            for (0..g.carry_bytes) |b| acc = acc.add(v.main(base + b).mul(k(F, @as(u32, 1) << @intCast(8 * b))));
            return acc.sub(v.main(L.ACTIVE).mul(k(F, @as(u32, 1) << @intCast(g.carry_bits - 1))));
        }
        fn modulusChunk(comptime F: type, v: anytype, i: usize) F {
            return switch (d.modulus) {
                .constant => v.main(L.ACTIVE).mul(k(F, L.modulusByte(2 * i) + 256 * L.modulusByte(2 * i + 1))),
                .variable => |m| chunk(F, v, L.column(.{ .in = m }), i),
            };
        }
        pub fn byteQuery(comptime F: type, v: anytype, index: usize) F {
            const q = L.QUERIES[index];
            const x = v.main(q.column);
            return if (q.addend == 0) x else x.add(k(F, q.addend));
        }

        /// MAIN-only authority. Emission order is protocol authority:
        /// Booleanity, nonzero proof, odd modulus, carried relations,
        /// canonical checks, activity prefix.
        pub fn emitMain(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
            const one = F.one();
            const active = v.main(L.ACTIVE);
            E.booleanFor(F, sink, active);
            for (L.BORROW) |base| for (0..L.CHUNKS - 1) |i| E.booleanFor(F, sink, v.main(base + i));
            if (d.nonzero) |nz| {
                for (0..L.CHUNKS) |i| E.booleanFor(F, sink, v.main(L.SEL + i));
                var sum = F.zero();
                var picked = F.zero();
                for (0..L.CHUNKS) |i| {
                    const sel = v.main(L.SEL + i);
                    sum = sum.add(sel);
                    var delta = chunk(F, v, L.column(nz.a), i);
                    if (nz.b) |b| delta = delta.sub(chunk(F, v, L.column(b), i));
                    picked = picked.add(sel.mul(delta));
                }
                sink.emit(sum.sub(active));
                sink.emit(picked.mul(v.main(L.INV)).sub(active));
            }
            if (d.odd_modulus) {
                const m = L.column(.{ .in = d.modulus.variable });
                sink.emit(v.main(m).sub(v.main(L.HALF).mul(k(F, 2))).sub(active));
            }
            inline for (0..L.RELATIONS) |r| {
                const g = L.GEOMETRY[r];
                const radix: u32 = @intCast(@as(u64, 1) << @intCast(8 * g.group));
                for (0..g.groups) |j| {
                    var sum = F.zero();
                    for (0..g.group) |offset| {
                        const n = g.group * j + offset;
                        if (n < g.coefficients) {
                            const c = coefficient(F, v, r, n);
                            sum = sum.add(if (offset == 0) c else c.mul(k(F, @as(u32, 1) << @intCast(8 * offset))));
                        }
                    }
                    if (j > 0) sum = sum.add(carry(F, v, r, j - 1));
                    sink.emit(sum.sub(carry(F, v, r, j).mul(k(F, radix))));
                }
            }
            // x + D + 1 = M over 16-bit chunks with Boolean carries, no final carry.
            for (L.CHECKS, L.D, L.BORROW) |check, dbase, bbase| {
                for (0..L.CHUNKS) |i| {
                    var e = chunk(F, v, L.column(check.x), i).add(chunk(F, v, dbase, i)).sub(modulusChunk(F, v, i));
                    if (i == 0) e = e.add(active);
                    if (i > 0) e = e.add(v.main(bbase + i - 1));
                    if (i + 1 < L.CHUNKS) e = e.sub(v.main(bbase + i).mul(k(F, 65536)));
                    sink.emit(e);
                }
            }
            const previous = v.previousActive();
            const first = v.fixed(Base.FIRST);
            sink.emit(first.mul(one.sub(active)));
            sink.emit(one.sub(first).mul(active).mul(one.sub(previous)));
            sink.emit(previous.mul(one.sub(active)).mul(v.fixed(Base.ROW).sub(E.callsFor(F, public))));
            sink.emit(v.fixed(Base.LAST).mul(active));
        }

        pub fn tuple(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), wire: usize) [Base.WIRE_ARITY]F {
            var out: [Base.WIRE_ARITY]F = undefined;
            out[0] = k(F, L.PROGRAM_KIND);
            out[1] = E.firstIdFor(F, public).add(v.fixed(Base.ROW));
            out[2] = k(F, L.wireLabel(wire));
            for (0..32) |b| out[3 + b] = v.main(if (wire < L.COORDS) L.PACKET + 32 * wire + b else L.afterColumn(wire - L.COORDS, b));
            return out;
        }
        fn secure(comptime F: type, v: anytype, start: usize, previous: bool) E.SecureFor(F) {
            const degree = comptime E.extensionDegree(E.ConstFor(F));
            const offset = start / 4 * degree;
            var c: [degree]F = undefined;
            for (&c, 0..) |*x, i| x.* = if (previous) v.previousInteraction(offset + i) else v.interaction(offset + i);
            return E.secureFromCoordinatesForField(E.ConstFor(F), F, c);
        }
        fn byteFraction(comptime F: type, v: anytype, ch: ChallengesFor(E.ConstFor(F)), index: usize) struct { F, E.SecureFor(F) } {
            const gamma = E.splatFor(F, ch.bytes);
            if (index < L.BYTE_QUERIES) return .{ F.one(), gamma.sub(E.liftFor(F, byteQuery(F, v, index))) };
            if (index == L.BYTE_QUERIES) return .{ v.main(L.MULT).neg(), gamma.sub(E.liftFor(F, v.fixed(Base.BYTE))) };
            return .{ F.zero(), E.SecureFor(F).one() };
        }
        /// delta * prod d_i - sum_i n_i prod_{j != i} d_j (degree BATCH + 1).
        fn batch(comptime F: type, delta: E.SecureFor(F), n: [L.BATCH]F, den: [L.BATCH]E.SecureFor(F), sink: *E.SinkFor(F)) void {
            if (L.BATCH == 2) {
                // Unchanged expression for the curve/field ops.
                sink.emit(delta.mul(den[0]).mul(den[1]).sub(E.mulBaseFor(F, den[1], n[0])).sub(E.mulBaseFor(F, den[0], n[1])));
                return;
            }
            var all = delta;
            for (den) |x| all = all.mul(x);
            var weighted = E.SecureFor(F).zero();
            inline for (0..L.BATCH) |i| {
                var others = E.SecureFor(F).one();
                inline for (0..L.BATCH) |j| if (j != i) {
                    others = others.mul(den[j]);
                };
                weighted = weighted.add(E.mulBaseFor(F, others, n[i]));
            }
            sink.emit(all.sub(weighted));
        }
        pub fn emit(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
            emitMain(F, v, public, sink);
            emitInteraction(F, v, public, claim, ch, sink);
        }

        pub fn emitInteraction(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
            for (0..L.BYTE_BATCHES) |b| {
                const current = secure(F, v, 4 * b, false);
                const prior = if (b == 0) secure(F, v, L.BYTE_LAST, true) else secure(F, v, 4 * (b - 1), false);
                var num: [L.BATCH]F = undefined;
                var den: [L.BATCH]E.SecureFor(F) = undefined;
                for (0..L.BATCH) |i| {
                    const f = byteFraction(F, v, ch, L.BATCH * b + i);
                    num[i] = f[0];
                    den[i] = f[1];
                }
                batch(F, current.sub(prior), num, den, sink);
            }
            // Inputs consumed (-active), written coordinates produced (+active).
            const active = v.main(L.ACTIVE);
            for (0..L.WIRE_BATCHES) |w| {
                const at = L.WIRE_FIRST + 4 * w;
                const current = secure(F, v, at, false);
                const prior = if (w == 0) secure(F, v, L.WIRE_LAST, true).sub(E.mulBaseFor(F, E.splatFor(F, claim), v.fixed(Base.FIRST))) else secure(F, v, at - 4, false);
                var den: [L.BATCH]E.SecureFor(F) = undefined;
                var num: [L.BATCH]F = undefined;
                for (0..L.BATCH) |i| {
                    const id = L.BATCH * w + i;
                    if (id < L.WIRE_FRACTIONS) {
                        den[i] = E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &tuple(F, v, public, id), true);
                        num[i] = if (id >= L.COORDS) active else active.neg();
                    } else {
                        den[i] = E.SecureFor(F).one();
                        num[i] = F.zero();
                    }
                }
                batch(F, current.sub(prior), num, den, sink);
            }
        }
    };
}
