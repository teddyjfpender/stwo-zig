//! Field-width regression for the materialization-free constant bucket path.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
fn exercise(a: std.mem.Allocator) !void {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 11));
    const expected = O.fromM31Array(coordinates);
    var accumulator = try engine.air.accumulation.ForField(O).DomainEvaluationAccumulator.init(a, O.one(), 5, 1);
    defer accumulator.deinit();
    try accumulator.accumulateConstant(3, expected);
    var column = try accumulator.finalize();
    defer column.deinit(a);
    for (0..column.len()) |i| try std.testing.expect(column.at(i).eql(expected));
}
test "OM31 constant-only composition writes all eight coordinate planes" {
    try exercise(std.testing.allocator);
}
test "OM31 constant composition allocation failures release every owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exercise, .{});
}
