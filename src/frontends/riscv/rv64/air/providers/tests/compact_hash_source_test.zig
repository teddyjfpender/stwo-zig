//! Regression for shared hash preparation at a matching committed LDE height.
//! A matching log does not imply an evaluation buffer is still resident.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const a = std.testing.allocator;
fn recover(allocator: std.mem.Allocator) !void {
    var coefficients: [16]M = undefined;
    for (&coefficients, 0..) |*value, i| value.* = M.fromCanonical(@intCast(i * i + 3));
    const poly = Poly{ .log_size = 5, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients) };
    try std.testing.expect(try support.sourceNeedsExtension(poly, 4, 5));
    var owned: [1][]M = undefined;
    var used: usize = 0;
    defer for (owned[0..used]) |values| allocator.free(values);
    const values = try support.evaluationValues(allocator, poly, 5, 32, &owned, &used);
    try std.testing.expectEqual(@as(usize, 1), used);
    try std.testing.expectEqualSlices(M, &coefficients, values[0..16]);
    for (values[16..]) |v| try std.testing.expect(v.isZero());
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var twiddles = try engine.poly.twiddles.precomputeM31(allocator, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(allocator, &twiddles);
    try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..used], domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
    const resident = Poly{ .log_size = 5, .values = values, .coefficients = poly.coefficients };
    try std.testing.expect(!try support.sourceNeedsExtension(resident, 4, 5));
    const direct = try support.evaluationValues(allocator, resident, 5, 32, &.{}, &used);
    try std.testing.expectEqual(values.ptr, direct.ptr);
    try std.testing.expectEqual(@as(usize, 32), direct.len);
}
test "compact hash source at matching LDE height recovers coefficients instead of empty evaluations" {
    try recover(a);
    try std.testing.checkAllAllocationFailures(a, recover, .{});
}
