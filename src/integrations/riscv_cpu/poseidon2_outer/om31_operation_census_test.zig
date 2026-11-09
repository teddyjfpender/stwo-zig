//! Diagnostic accounting only; counts actual emitted QM31 rows and preserves
//! source topology. No whole-prover speedup follows from operation counts alone.
const std = @import("std");
const core = @import("stwo_core");
const Lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const C = @import("full_p2_common.zig");
const P = @import("context.zig");
fn build(a: std.mem.Allocator, counts: ?*Lane.Census) !P.Context {
    var scope: ?Lane.CensusScope = if (counts) |value| Lane.CensusScope.init(value) else null;
    defer if (scope) |*value| value.deinit();
    var structural = Lane.StructuralScope.init();
    defer structural.deinit();
    var owner = try P.Context.init(a, 2);
    errdefer owner.deinit();
    C.lane.begin(owner.algebra());
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const x = try C.F.guess(owner.algebra(), C.O.fromM31Array(.{core.fields.m31.M31.fromCanonical(2)} ** 8));
    const y = try C.F.guess(owner.algebra(), C.O.fromM31Array(.{core.fields.m31.M31.fromCanonical(3)} ** 8));
    const product = x.mul(y);
    const inner = product.mulInner(x.c0);
    const sum = product.add(inner);
    try C.lane.finish();
    active = false;
    try owner.setOutputs(&.{ sum.c0.v, sum.c1.v });
    try owner.finalize();
    return owner;
}
test "OP OM31 operation census records disjoint actual rows without changing source topology" {
    const a = std.testing.allocator;
    var counts: Lane.Census = .{};
    var measured = try build(a, &counts);
    defer measured.deinit();
    var control = try build(a, null);
    defer control.deinit();
    try std.testing.expectEqualDeep(control.base.gate_counts, measured.base.gate_counts);
    try std.testing.expectEqualDeep(control.base.circuit.mul.items, measured.base.circuit.mul.items);
    try std.testing.expectEqualDeep(control.base.circuit.add.items, measured.base.circuit.add.items);
    try std.testing.expectEqualDeep(control.base.circuit.sub.items, measured.base.circuit.sub.items);
    try std.testing.expectEqual(@as(u64, 1), counts.get(.full_mul).calls);
    try std.testing.expectEqual(@as(u64, 7), counts.get(.full_mul).qm31_rows);
    try std.testing.expectEqual(@as(u64, 1), counts.get(.mul_inner).calls);
    try std.testing.expectEqual(@as(u64, 2), counts.get(.mul_inner).qm31_rows);
    try std.testing.expectEqual(@as(u64, 1), counts.get(.add).calls);
    try std.testing.expectEqual(@as(u64, 2), counts.get(.add).qm31_rows);
    try std.testing.expectEqual(@as(u64, 11), counts.classifiedRows());
    try std.testing.expect(try measured.isCircuitValid());
}
