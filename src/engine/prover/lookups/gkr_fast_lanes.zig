//! Four-lane secure arithmetic shared by packed GKR traversal.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const OM31 = core.fields.om31.OM31;
const m31 = core.fields.m31;
const PE = core.fields.packed_extensions;
const V = m31.Vec4u32;

/// Four-lane packed arithmetic for a secure field: QM31 directly, OM31 as a
/// Karatsuba quadratic over packed QM31 (`OM31 = QM31[v]/(v^2 - u)`).
pub fn Lanes(comptime S: type) type {
    if (S == QM31) return struct {
        pub const T = PE.PackedQM31x4;
        pub inline fn load(p: [*]const S) T {
            return PE.loadPackedQM31x4(p);
        }
        pub inline fn store(p: [*]S, x: T) void {
            PE.storePackedQM31x4(p, x);
        }
        pub const add = PE.addPackedQM31x4;
        pub const sub = PE.subPackedQM31x4;
        pub const mul = PE.mulPackedQM31x4;
        pub const splat = PE.splatPackedQM31x4;
        pub const zero = PE.zeroPackedQM31x4;
        pub const evenOdd = PE.evenOddPackedQM31x4;
        pub const interleave = PE.interleavePackedQM31x4;
        pub const sumLanes = PE.sumLanesPackedQM31x4;
        pub inline fn mulBase(x: T, b: V) T {
            return .{ .c0a = m31.mulVec4(x.c0a, b), .c0b = m31.mulVec4(x.c0b, b), .c1a = m31.mulVec4(x.c1a, b), .c1b = m31.mulVec4(x.c1b, b) };
        }
        pub inline fn fromBase(b: V) T {
            return .{ .c0a = b, .c0b = @splat(0), .c1a = @splat(0), .c1b = @splat(0) };
        }
    };
    if (S == OM31) return struct {
        const Q = Lanes(QM31);
        pub const T = struct { c0: Q.T, c1: Q.T };
        comptime {
            std.debug.assert(@sizeOf(OM31) == 2 * @sizeOf(QM31));
            std.debug.assert(@offsetOf(OM31, "c0") == 0 and @offsetOf(OM31, "c1") == @sizeOf(QM31));
        }
        pub inline fn load(p: [*]const S) T {
            const q: [*]const QM31 = @ptrCast(p);
            const x = Q.evenOdd(Q.load(q), Q.load(q + 4));
            return .{ .c0 = x[0], .c1 = x[1] };
        }
        pub inline fn store(p: [*]S, x: T) void {
            const q: [*]QM31 = @ptrCast(p);
            const y = Q.interleave(x.c0, x.c1);
            Q.store(q, y[0]);
            Q.store(q + 4, y[1]);
        }
        pub inline fn add(x: T, y: T) T {
            return .{ .c0 = Q.add(x.c0, y.c0), .c1 = Q.add(x.c1, y.c1) };
        }
        pub inline fn sub(x: T, y: T) T {
            return .{ .c0 = Q.sub(x.c0, y.c0), .c1 = Q.sub(x.c1, y.c1) };
        }
        /// (a + b v)(c + d v) = (ac + u bd) + ((a + b)(c + d) - ac - bd) v.
        pub inline fn mul(x: T, y: T) T {
            const ac = Q.mul(x.c0, y.c0);
            const bd = Q.mul(x.c1, y.c1);
            const cross = Q.sub(Q.sub(Q.mul(Q.add(x.c0, x.c1), Q.add(y.c0, y.c1)), ac), bd);
            return .{ .c0 = Q.add(ac, mulByU(bd)), .c1 = cross };
        }
        /// (a + b u) u = (2 + i) b + a u, coordinate-wise as in om31.NativeOps.
        inline fn mulByU(x: Q.T) Q.T {
            return .{
                .c0a = m31.subVec4(m31.addVec4(x.c1a, x.c1a), x.c1b),
                .c0b = m31.addVec4(x.c1a, m31.addVec4(x.c1b, x.c1b)),
                .c1a = x.c0a,
                .c1b = x.c0b,
            };
        }
        pub inline fn splat(x: S) T {
            return .{ .c0 = Q.splat(x.c0), .c1 = Q.splat(x.c1) };
        }
        pub inline fn zero() T {
            return .{ .c0 = Q.zero(), .c1 = Q.zero() };
        }
        pub inline fn evenOdd(lo: T, hi: T) [2]T {
            const a = Q.evenOdd(lo.c0, hi.c0);
            const b = Q.evenOdd(lo.c1, hi.c1);
            return .{ .{ .c0 = a[0], .c1 = b[0] }, .{ .c0 = a[1], .c1 = b[1] } };
        }
        pub inline fn interleave(even: T, odd: T) [2]T {
            const a = Q.interleave(even.c0, odd.c0);
            const b = Q.interleave(even.c1, odd.c1);
            return .{ .{ .c0 = a[0], .c1 = b[0] }, .{ .c0 = a[1], .c1 = b[1] } };
        }
        pub inline fn sumLanes(x: T) S {
            return .{ .c0 = Q.sumLanes(x.c0), .c1 = Q.sumLanes(x.c1) };
        }
        pub inline fn mulBase(x: T, b: V) T {
            return .{ .c0 = Q.mulBase(x.c0, b), .c1 = Q.mulBase(x.c1, b) };
        }
        pub inline fn fromBase(b: V) T {
            return .{ .c0 = Q.fromBase(b), .c1 = Q.zero() };
        }
    };
    @compileError("no packed lanes for this secure field");
}
