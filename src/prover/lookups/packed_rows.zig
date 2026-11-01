//! Native SIMD numerical kernels mirroring Stwo's SIMD lookup backend.
//! Scalar AoS owners and pool partitioning stay unchanged; only a native pack
//! is transposed at a time. Every range admits unaligned starts/scalar tails.
const core = @import("stwo_core");
const m = core.fields.m31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const pq = core.fields.packed_qm31;
const po = core.fields.packed_om31;
pub const WIDTH = m.PACK_WIDTH;
pub fn ForField(comptime S: type) type {
    if (S != Q and S != O) @compileError("unsupported packed GKR secure field");
    return struct {
        pub const P = if (S == Q) pq.PackedQM31 else po.PackedOM31;
        /// Preserve the packed arithmetic authority while eliminating the
        /// aggregate-by-value call ABI in numerical row kernels.
        pub inline fn mul(a: P, b: P) P {
            @setEvalBranchQuota(100000);
            return @call(.always_inline, P.mul, .{ a, b });
        }
        pub inline fn splat(x: S) P {
            return if (S == Q) P.splat(x) else po.splat(x);
        }
        pub inline fn lane(x: P, i: usize) S {
            return if (S == Q) x.lane(i) else po.lane(x, i);
        }
        pub inline fn load(values: []const S, start: usize, comptime stride: usize) P {
            if (S == O and stride == 1) return po.loadNative(values[start..]);
            var c: [if (S == Q) 4 else 8]m.PackedM31 = undefined;
            inline for (0..WIDTH) |i| {
                const x = values[start + i * stride];
                if (S == Q) {
                    c[0][i] = x.c0.a.v;
                    c[1][i] = x.c0.b.v;
                    c[2][i] = x.c1.a.v;
                    c[3][i] = x.c1.b.v;
                } else {
                    c[0][i] = x.c0.c0.a.v;
                    c[1][i] = x.c0.c0.b.v;
                    c[2][i] = x.c0.c1.a.v;
                    c[3][i] = x.c0.c1.b.v;
                    c[4][i] = x.c1.c0.a.v;
                    c[5][i] = x.c1.c0.b.v;
                    c[6][i] = x.c1.c1.a.v;
                    c[7][i] = x.c1.c1.b.v;
                }
            }
            return if (S == Q) P.fromCoordinates(c) else po.fromCoordinates(c);
        }
        pub inline fn base(values: []const m.M31, start: usize, comptime stride: usize) m.PackedM31 {
            if (stride == 1) return m.loadPacked(values[start..].ptr);
            var out: m.PackedM31 = undefined;
            inline for (0..WIDTH) |i| out[i] = values[start + i * stride].v;
            return out;
        }
        pub inline fn store(values: []S, start: usize, x: P) void {
            if (S == O) return po.storeNative(values[start..], x);
            inline for (0..WIDTH) |i| values[start + i] = x.lane(i);
        }
        pub inline fn sum(x: P) S {
            @setEvalBranchQuota(100000);
            var out = S.zero();
            inline for (0..WIDTH) |i| out = out.add(lane(x, i));
            return out;
        }
        pub inline fn numerator(comptime F: type, values: []const F, start: usize, comptime stride: usize) if (F == m.M31) m.PackedM31 else P {
            return if (F == m.M31) base(values, start, stride) else load(values, start, stride);
        }
        pub inline fn cross(comptime F: type, n: if (F == m.M31) m.PackedM31 else P, d: P) P {
            return if (F == m.M31) d.mulBase(n) else mul(d, n);
        }
        pub inline fn numTwo(comptime F: type, a: if (F == m.M31) m.PackedM31 else P, b: if (F == m.M31) m.PackedM31 else P) if (F == m.M31) m.PackedM31 else P {
            return if (F == m.M31) m.subPacked(m.addPacked(b, b), a) else b.add(b).sub(a);
        }
        pub fn fold(comptime F: type, input: []const F, output: []S, challenge: S, first: usize, end: usize) usize {
            const r = splat(challenge);
            var i = first;
            while (i + WIDTH <= end) : (i += WIDTH) {
                if (F == m.M31) {
                    const a = base(input, i, 1);
                    const b = base(input, i + output.len, 1);
                    const result = r.mulBase(m.subPacked(b, a)).add(if (S == Q) P.fromBase(a) else po.fromCoordinates(.{ a, @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0) }));
                    store(output, i, result);
                } else {
                    const a = load(input, i, 1);
                    const b = load(input, i + output.len, 1);
                    store(output, i, mul(r, b.sub(a)).add(a));
                }
            }
            return i;
        }
        pub fn nextProduct(input: []const S, output: []S, first: usize, end: usize) usize {
            var i = first;
            while (i + WIDTH <= end) : (i += WIDTH) store(output, i, mul(load(input, 2 * i, 2), load(input, 2 * i + 1, 2)));
            return i;
        }
        pub fn nextLogup(comptime F: type, nums: []const F, dens: []const S, out_n: []S, out_d: []S, first: usize, end: usize) usize {
            var i = first;
            while (i + WIDTH <= end) : (i += WIDTH) {
                const a = load(dens, 2 * i, 2);
                const b = load(dens, 2 * i + 1, 2);
                const n = if (F == void) a.add(b) else cross(F, numerator(F, nums, 2 * i, 2), b).add(cross(F, numerator(F, nums, 2 * i + 1, 2), a));
                store(out_n, i, n);
                store(out_d, i, mul(a, b));
            }
            return i;
        }
        pub const SumResult = struct { values: [2]S, end: usize };
        pub fn sumProduct(eq: []const S, input: []const S, terms: usize, first: usize, end: usize) SumResult {
            var s0 = splat(S.zero());
            var s2 = splat(S.zero());
            var i = first;
            while (i + WIDTH <= end) : (i += WIDTH) {
                const a = load(input, 2 * i, 2);
                const b = load(input, 2 * i + 1, 2);
                const a1 = load(input, 2 * (terms + i), 2);
                const b1 = load(input, 2 * (terms + i) + 1, 2);
                const a2 = a1.add(a1).sub(a);
                const b2 = b1.add(b1).sub(b);
                const e = load(eq, i, 1);
                s0 = s0.add(mul(e, mul(a, b)));
                s2 = s2.add(mul(e, mul(a2, b2)));
            }
            return .{ .values = .{ sum(s0), sum(s2) }, .end = i };
        }
        /// Rank-two weighted LogUp gate. Grouping λ*a with nA avoids the
        /// standalone a*b product: four secure products including Eq instead
        /// of five for generic numerators; base leaves save one base product.
        /// This changes only arithmetic scheduling, not the scalar authority.
        inline fn weightedLogupGate(comptime F: type, na: if (F == m.M31) m.PackedM31 else P, nb: if (F == m.M31) m.PackedM31 else P, a: P, b: P, lambda: P) P {
            const promoted = if (F == m.M31)
                if (S == Q) P.fromBase(na) else po.fromCoordinates(.{ na, @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0), @splat(0) })
            else
                na;
            return mul(promoted.add(mul(lambda, a)), b).add(cross(F, nb, a));
        }
        pub fn sumLogup(comptime F: type, eq: []const S, nums: []const F, dens: []const S, terms: usize, lambda: S, first: usize, end: usize) SumResult {
            var s0 = splat(S.zero());
            var s2 = splat(S.zero());
            var i = first;
            const l = splat(lambda);
            while (i + WIDTH <= end) : (i += WIDTH) {
                const a = load(dens, 2 * i, 2);
                const b = load(dens, 2 * i + 1, 2);
                const a1 = load(dens, 2 * (terms + i), 2);
                const b1 = load(dens, 2 * (terms + i) + 1, 2);
                const a2 = a1.add(a1).sub(a);
                const b2 = b1.add(b1).sub(b);
                const gate0 = if (F == void) a.add(b).add(mul(l, mul(a, b))) else weightedLogupGate(F, numerator(F, nums, 2 * i, 2), numerator(F, nums, 2 * i + 1, 2), a, b, l);
                const gate2 = if (F == void) a2.add(b2).add(mul(l, mul(a2, b2))) else weightedLogupGate(F, numTwo(F, numerator(F, nums, 2 * i, 2), numerator(F, nums, 2 * (terms + i), 2)), numTwo(F, numerator(F, nums, 2 * i + 1, 2), numerator(F, nums, 2 * (terms + i) + 1, 2)), a2, b2, l);
                const e = load(eq, i, 1);
                s0 = s0.add(mul(e, gate0));
                s2 = s2.add(mul(e, gate2));
            }
            return .{ .values = .{ sum(s0), sum(s2) }, .end = i };
        }
    };
}
