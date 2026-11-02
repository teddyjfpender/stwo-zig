//! Dense affine-line degree audit of the sole full CPU residual dispatcher.
//! Diagnostic only; finite differences give a reproducible counterexample when
//! a declared bound fails, not a replacement for a symbolic degree argument.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").rv64_air;
const E = air.evaluation;
const Q = E.Q;
const Component = air.full.component.Component;
pub const Violation = struct { constraint_index: usize, observed_degree_at_least: u32, fifth_difference: [4]u32 };
pub const Result = struct {
    allocator: std.mem.Allocator,
    constraints: usize,
    samples: u32,
    violations: []Violation,
    pub fn deinit(self: *Result) void {
        self.allocator.free(self.violations);
        self.* = undefined;
    }
};
pub fn inspect(a: std.mem.Allocator, component: *const Component, seed: u64) !Result {
    const count = component.constraint_count;
    const width = component.mainCount();
    const inter = component.interactionCount();
    const total = 3 + 2 * width + 2 * inter;
    const base = try a.alloc(Q, total);
    defer a.free(base);
    const slope = try a.alloc(Q, total);
    defer a.free(slope);
    const point = try a.alloc(Q, total);
    defer a.free(point);
    const rows = try a.alloc(Q, 9 * count);
    defer a.free(rows);
    var prng = std.Random.DefaultPrng.init(seed);
    for (base, slope) |*b, *s| {
        b.* = randomQ(prng.random());
        s.* = randomQ(prng.random());
    }
    for (0..9) |t| {
        for (point, base, slope) |*value, b, s| value.* = b.add(s.mul(E.q(@intCast(t))));
        var sink = E.Sink{ .values = rows[t * count ..][0..count] };
        component.emit(point[0..3].*, point[3..][0..width], point[3 + width ..][0..width], point[3 + 2 * width ..][0..inter], point[3 + 2 * width + inter ..][0..inter], &sink);
        if (sink.count != count) return error.CpuDegreeDiagnosticShape;
    }
    var violations: std.ArrayList(Violation) = .empty;
    errdefer violations.deinit(a);
    for (0..count) |c| {
        var differences: [9]Q = undefined;
        for (&differences, 0..) |*value, t| value.* = rows[t * count + c];
        var degree: u32 = 0;
        var fifth = Q.zero();
        for (0..9) |order| {
            if (!differences[0].isZero()) degree = @intCast(order);
            if (order == 5) fifth = differences[0];
            if (order != 8) for (0..8 - order) |i| {
                differences[i] = differences[i + 1].sub(differences[i]);
            };
        }
        if (!fifth.isZero()) {
            var coordinates: [4]u32 = undefined;
            for (&coordinates, fifth.toM31Array()) |*coordinate, value| coordinate.* = value.v;
            try violations.append(a, .{ .constraint_index = c, .observed_degree_at_least = degree, .fifth_difference = coordinates });
        }
    }
    return .{ .allocator = a, .constraints = count, .samples = 9, .violations = try violations.toOwnedSlice(a) };
}
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus));
}
