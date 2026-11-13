//! interaction cases; fixture authority is shared with the other test owners.
//! Constraint-level authority tests for the curve/field truth AIRs. The
//! reference is an independent std.math.big oracle (Fermat inverses, plain
//! big-integer reduction), plus self-certifying group-law checks.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const Base = @import("layout.zig");
const TraceOf = @import("trace.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const MODULUS = core.fields.m31.Modulus;

const Support = @import("tests_support.zig");
const q = Support.q;
const Harness = Support.Harness;
const KEYS = Support.KEYS;
const challenges = Support.challenges;

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

test "packed 16-lane residuals equal scalar residuals and every constraint has degree at most Layout.DEGREE (3 curve, 4 secp row)" {
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
        // Each residual along a QM31 line: the (DEGREE + 1)-th difference
        // vanishes and some DEGREE-th difference does not.
        const STEPS = L.DEGREE + 2;
        const rows = try a.alloc(Q, STEPS * L.CONSTRAINTS);
        defer a.free(rows);
        for (0..STEPS) |step| {
            for (values, 0..) |*x, c| {
                const intercept = Q.fromU32Unchecked(@intCast(1 + c), 2, 3, 4);
                const slope = Q.fromU32Unchecked(5, @intCast(6 + c), 7, 8);
                x.* = intercept.add(slope.mulM31(M.fromCanonical(@intCast(step))));
            }
            const view = viewFrom(values);
            var sink = E.Sink{ .values = rows[step * L.CONSTRAINTS ..][0..L.CONSTRAINTS] };
            H.Eq.emit(Q, &view, span, claim, ch, &sink);
        }
        const difference = struct {
            fn at(all: []const Q, order: usize, k: usize) Q {
                var acc = Q.zero();
                var binomial: u64 = 1;
                for (0..order + 1) |i| {
                    const term = all[i * L.CONSTRAINTS + k].mulM31(M.fromCanonical(@intCast(binomial)));
                    acc = if ((order - i) % 2 == 0) acc.add(term) else acc.sub(term);
                    binomial = binomial * (order - i) / (i + 1);
                }
                return acc;
            }
        }.at;
        var full_degree = false;
        for (0..L.CONSTRAINTS) |c| {
            full_degree = full_degree or !difference(rows, L.DEGREE, c).isZero();
            try std.testing.expect(difference(rows, L.DEGREE + 1, c).isZero());
        }
        try std.testing.expect(full_degree);
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
