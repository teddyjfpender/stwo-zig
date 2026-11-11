//! Immutable quadratic homogeneous G2 transition program, preserving the exact
//! existing Miller line normalization. No new VM operation or admission.
const std = @import("std");
pub const B = @import("../curves/spec.zig");
pub const Kind = enum { doubling, addition };
pub const UNUSED = 255;
pub const MAX_VALUES = 40;
pub const MAX_TERMS = 24;
pub const FQ2 = [2]u256;
pub const Point = [3]FQ2;
pub const TWIST_B: FQ2 = .{ 19485874751759354771024239261021720505790618469301721065564631296452457478373, 266929791119991161246907387137283842545076965332900288569378510910307636690 };
pub fn rows(kind: Kind) usize {
    return if (kind == .doubling) 24 else 22;
}
pub fn initialCount(kind: Kind) usize {
    return if (kind == .doubling) 9 else 10;
}
pub fn inputs(kind: Kind) usize {
    return if (kind == .doubling) 6 else 10;
}
const Monomial = struct { a: u8, b: ?u8 = null, coefficient: i32 };
const Poly = struct {
    list: [MAX_TERMS]Monomial = undefined,
    len: usize = 0,
    fn variable(id: u8) Poly {
        var p = Poly{};
        p.list[0] = .{ .a = id, .coefficient = 1 };
        p.len = 1;
        return p;
    }
    fn insert(p: *Poly, t: Monomial) void {
        if (t.coefficient == 0) return;
        for (p.list[0..p.len]) |*old| if (old.a == t.a and old.b == t.b) {
            old.coefficient += t.coefficient;
            return;
        };
        std.debug.assert(p.len < MAX_TERMS);
        p.list[p.len] = t;
        p.len += 1;
    }
    fn add(a: Poly, b: Poly) Poly {
        var p = a;
        for (b.list[0..b.len]) |t| p.insert(t);
        return p;
    }
    fn scale(a: Poly, k: i32) Poly {
        var p = a;
        for (p.list[0..p.len]) |*t| t.coefficient *= k;
        return p;
    }
    fn sub(a: Poly, b: Poly) Poly {
        return Poly.add(a, Poly.scale(b, -1));
    }
    fn mul(a: Poly, b: Poly) Poly {
        var p = Poly{};
        for (a.list[0..a.len]) |x| for (b.list[0..b.len]) |y| {
            std.debug.assert(x.b == null and y.b == null);
            p.insert(.{ .a = @min(x.a, y.a), .b = @max(x.a, y.a), .coefficient = x.coefficient * y.coefficient });
        };
        return p;
    }
};
const Pair = [2]Poly;
fn pair(id: u8) Pair {
    return .{ Poly.variable(id), Poly.variable(id + 1) };
}
fn add(a: Pair, b: Pair) Pair {
    return .{ a[0].add(b[0]), a[1].add(b[1]) };
}
fn sub(a: Pair, b: Pair) Pair {
    return .{ a[0].sub(b[0]), a[1].sub(b[1]) };
}
fn scale(a: Pair, k: i32) Pair {
    return .{ a[0].scale(k), a[1].scale(k) };
}
fn mul(a: Pair, b: Pair) Pair {
    return .{ a[0].mul(b[0]).sub(a[1].mul(b[1])), a[0].mul(b[1]).add(a[1].mul(b[0])) };
}
pub const Operation = struct { expression: Poly, writer: u8 };
pub const Program = struct {
    operations: [24]Operation = undefined,
    count: usize = 0,
    initial: u8,
    point: [6]u8 = undefined,
    line: [6]u8 = undefined,
    line_scale: [3]i32 = undefined,
    fn write(self: *Program, p: Pair) Pair {
        const first: u8 = self.initial + @as(u8, @intCast(self.count));
        for (p) |expression| {
            self.operations[self.count] = .{ .expression = expression, .writer = self.initial + @as(u8, @intCast(self.count)) };
            self.count += 1;
        }
        return pair(first);
    }
    fn id(p: Poly) u8 {
        std.debug.assert(p.len == 1 and p.list[0].b == null and p.list[0].coefficient == 1);
        return p.list[0].a;
    }
    fn finish(self: *Program, x: Pair, y: Pair, z: Pair, line: [3]Pair, scales: [3]i32) void {
        const point = [_]Pair{ x, y, z };
        for (point, 0..) |p, i| for (p, 0..) |v, j| {
            self.point[2 * i + j] = id(v);
        };
        for (line, 0..) |p, i| for (p, 0..) |v, j| {
            self.line[2 * i + j] = id(v);
        };
        self.line_scale = scales;
    }
};
pub fn program(comptime kind: Kind) Program {
    @setEvalBranchQuota(1_000_000);
    var p = Program{ .initial = @intCast(initialCount(kind)) };
    const x = pair(0);
    const y = pair(2);
    const z = pair(4);
    if (kind == .doubling) {
        const half = Poly.variable(6);
        const twist = pair(7);
        const k = p.write(mul(x, y));
        const a = p.write(.{ k[0].mul(half), k[1].mul(half) });
        const b = p.write(mul(y, y));
        const c = p.write(mul(z, z));
        const e = p.write(scale(mul(twist, c), 3));
        const sum = add(b, scale(e, 3));
        const g = p.write(.{ sum[0].mul(half), sum[1].mul(half) });
        const h = p.write(scale(mul(y, z), 2));
        const j = p.write(mul(x, x));
        const xx = p.write(mul(a, sub(b, scale(e, 3))));
        const yy = p.write(sub(mul(g, g), scale(mul(e, e), 3)));
        const zz = p.write(mul(b, h));
        const ii = p.write(sub(e, b));
        p.finish(xx, yy, zz, .{ h, j, ii }, .{ -1, 3, 1 });
    } else {
        const qx = pair(6);
        const qy = pair(8);
        const t = p.write(sub(y, mul(qy, z)));
        const l = p.write(sub(x, mul(qx, z)));
        const c = p.write(mul(t, t));
        const d = p.write(mul(l, l));
        const e = p.write(mul(l, d));
        const f = p.write(mul(z, c));
        const g = p.write(mul(x, d));
        const h = sub(add(e, f), scale(g, 2));
        const xx = p.write(mul(l, h));
        const yy = p.write(sub(mul(t, sub(g, h)), mul(e, y)));
        const zz = p.write(mul(z, e));
        const j = p.write(sub(mul(t, qx), mul(l, qy)));
        p.finish(xx, yy, zz, .{ l, t, j }, .{ 1, -1, 1 });
    }
    std.debug.assert(p.count == rows(kind));
    return p;
}
pub fn operandIds(comptime kind: Kind, comptime step: usize) [inputs(kind)]u8 {
    const p = comptime program(kind);
    const op = p.operations[step];
    var used: [MAX_VALUES]bool = @splat(false);
    for (op.expression.list[0..op.expression.len]) |t| if (t.coefficient != 0) {
        used[t.a] = true;
        if (t.b) |b| used[b] = true;
    };
    var ids: [inputs(kind)]u8 = @splat(UNUSED);
    var n: usize = 0;
    for (used, 0..) |yes, id| if (yes) {
        std.debug.assert(n < ids.len and id < op.writer);
        ids[n] = @intCast(id);
        n += 1;
    };
    return ids;
}
pub fn terms(comptime kind: Kind, comptime step: usize) []const B.Term {
    const result = comptime blk: {
        const p = program(kind);
        const op = p.operations[step];
        const ids = operandIds(kind, step);
        var list: [MAX_TERMS + 1]B.Term = undefined;
        var n: usize = 0;
        for (op.expression.list[0..op.expression.len]) |t| if (t.coefficient != 0) {
            var a: u8 = UNUSED;
            var b: u8 = UNUSED;
            for (ids, 0..) |id, i| {
                if (id == t.a) a = @intCast(i);
                if (t.b != null and id == t.b.?) b = @intCast(i);
            }
            std.debug.assert(a != UNUSED and (t.b == null or b != UNUSED));
            list[n] = .{ .a = .{ .in = a }, .b = if (t.b != null) .{ .in = b } else null, .coef = t.coefficient };
            n += 1;
        };
        list[n] = .{ .a = .{ .out = 0 }, .coef = -1 };
        n += 1;
        break :blk list[0..n].*;
    };
    return &result;
}
pub fn envelope(comptime kind: Kind) B.Def {
    const mass = comptime blk: {
        var maximum: [4]i32 = @splat(0);
        for (0..rows(kind)) |step| {
            var current: [4]i32 = @splat(0);
            for (terms(kind, step)) |t| current[(if (t.b != null) @as(usize, 0) else 2) + @as(usize, @intFromBool(t.coef < 0))] += @intCast(@abs(t.coef));
            for (&maximum, current) |*a, b| a.* = @max(a.*, b);
        }
        break :blk maximum;
    };
    const relation = &[_]B.Term{
        .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = mass[0] }, .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = -mass[1] },
        .{ .a = .{ .in = 4 }, .coef = mass[2] },                    .{ .a = .{ .out = 0 }, .coef = -mass[3] },
    };
    return .{ .limbs = 32, .coords = inputs(kind), .written = 1, .inputs = inputs(kind), .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .asymmetric_carries = true, .relations = &.{relation} };
}
pub fn commonGeometry(comptime kind: Kind) B.RelationGeometry {
    const d = envelope(kind);
    return B.deriveRelation(d, d.relations[0]);
}
pub fn fanout(comptime kind: Kind) [MAX_VALUES]u32 {
    var counts: [MAX_VALUES]u32 = @splat(0);
    inline for (0..rows(kind)) |step| for (operandIds(kind, step)) |id| if (id != UNUSED) {
        counts[id] += 1;
    };
    const p = program(kind);
    for (p.point) |id| counts[id] += 1;
    for (p.line) |id| counts[id] += 1;
    return counts;
}
