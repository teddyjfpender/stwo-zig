//! Bounded source preparation for framework composition. This owns only
//! temporary representations of the exact committed polynomial, never claims.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = engine.air.component_prover;
const Circle = engine.poly.circle;
const M = core.fields.m31.M31;
pub const Kind = enum { evaluations, coefficients };
pub const Materialized = struct {
    values: []const M,
    kind: Kind,
    owned: ?[]const M = null,
    recovered: bool = false,
    pub fn deinit(self: *Materialized, a: std.mem.Allocator) void {
        if (self.owned) |data| a.free(data);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, poly: C.Poly, log: u32) !Materialized {
    if (log < 1 or log > 30) return error.InvalidCudaFrameworkGeometry;
    try poly.validate();
    const rows = @as(usize, 1) << @intCast(log);
    if (poly.log_size == log and poly.values.len == rows) return .{ .values = poly.values, .kind = .evaluations };
    var recovered: ?Circle.CircleCoefficients = null;
    defer if (recovered) |*coeff| coeff.deinit(a);
    var coefficients = poly.coefficients orelse blk: {
        recovered = try Circle.poly.interpolateFromEvaluation(a, try Circle.CircleEvaluation.init(Circle.CanonicCoset.new(poly.log_size).circleDomain(), poly.values));
        break :blk recovered.?;
    };
    var values = coefficients.coefficients();
    // Recovered LDE coefficients can include an exactly zero suffix. This is
    // verified, not assumed from a claimed degree or blindly truncated.
    if (values.len > rows) {
        for (values[rows..]) |m| if (!m.eql(M.zero())) return error.CudaFrameworkPolynomialTooWide;
        values = values[0..rows];
        coefficients = try Circle.CircleCoefficients.initBorrowed(values);
    }
    const half = rows / 2;
    if (log >= 3) {
        var fits = values.len <= half;
        if (!fits) {
            fits = true;
            for (values[half..]) |m| if (!m.eql(M.zero())) {
                fits = false;
                break;
            };
        }
        if (fits) {
            const selected = values[0..@min(values.len, half)];
            const owned = if (recovered) |coeff| coeff.coefficients() else null;
            recovered = null;
            return .{ .values = selected, .kind = .coefficients, .owned = owned, .recovered = owned != null };
        }
    }
    const evaluation = try coefficients.evaluate(a, Circle.CanonicCoset.new(log).circleDomain());
    return .{ .values = evaluation.values, .kind = .evaluations, .owned = evaluation.values, .recovered = recovered != null };
}
pub const Job = struct {
    allocator: std.mem.Allocator,
    poly: C.Poly,
    log: u32,
    result: ?Materialized = null,
    failure: ?anyerror = null,
    pub fn run(self: *Job) void {
        self.result = prepare(self.allocator, self.poly, self.log) catch |err| {
            self.failure = err;
            return;
        };
    }
};

test "framework source preparation binds exact recovered coefficients and wider tails" {
    const a = std.testing.allocator;
    const coefficients = [_]M{ M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7), M.fromCanonical(11) };
    const poly = try Circle.CircleCoefficients.initBorrowed(&coefficients);
    const eval = try poly.evaluate(a, Circle.CanonicCoset.new(4).circleDomain());
    defer a.free(eval.values);
    var from_coeff = try prepare(a, .{ .log_size = 4, .values = &.{}, .coefficients = poly }, 5);
    defer from_coeff.deinit(a);
    try std.testing.expectEqual(Kind.coefficients, from_coeff.kind);
    try std.testing.expectEqualSlices(M, &coefficients, from_coeff.values);
    var recovered = try prepare(a, .{ .log_size = 4, .values = eval.values }, 5);
    defer recovered.deinit(a);
    try std.testing.expect(recovered.recovered);
    const oracle = try poly.evaluate(a, Circle.CanonicCoset.new(5).circleDomain());
    defer a.free(oracle.values);
    const restored = try (try Circle.CircleCoefficients.initBorrowed(recovered.values)).evaluate(a, Circle.CanonicCoset.new(5).circleDomain());
    defer a.free(restored.values);
    try std.testing.expectEqualSlices(M, oracle.values, restored.values);
    var direct = try prepare(a, .{ .log_size = 4, .values = eval.values }, 4);
    defer direct.deinit(a);
    try std.testing.expect(direct.owned == null);
    try std.testing.expectEqualSlices(M, eval.values, direct.values);
    var too_wide: [32]M = @splat(M.zero());
    too_wide[31] = M.one();
    const wide = try Circle.CircleCoefficients.initBorrowed(&too_wide);
    try std.testing.expectError(error.CudaFrameworkPolynomialTooWide, prepare(a, .{ .log_size = 5, .values = &.{}, .coefficients = wide }, 4));
    var full = try prepare(a, .{ .log_size = 5, .values = &.{}, .coefficients = wide }, 5);
    defer full.deinit(a);
    try std.testing.expectEqual(Kind.evaluations, full.kind);
}
