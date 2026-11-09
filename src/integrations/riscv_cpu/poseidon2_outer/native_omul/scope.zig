//! Explicit source-emission scope. Outside this scope all shared OM31 lanes
//! retain their historical gate lists and protocol defaults.
const Lane = @import("../../rv64_recursion/om31_circuit_lane.zig");
const QLane = @import("../../rv64_recursion/circuit_lane.zig");
const Common = @import("../../rv64_recursion/om31_poseidon/common.zig");
const B = @import("stwo_circuit_frontend").builder;
fn emit(a: Lane.Lane, b: Lane.Lane) B.context.Error!Lane.Lane {
    const owner = Common.sidecar(QLane.currentContext()) catch return error.InvalidWitnessOrigin;
    const outputs = try owner.nativeOmul(.{ a.c0.v, a.c1.v, b.c0.v, b.c1.v });
    return Lane.Lane.wire(outputs[0], outputs[1]);
}
pub fn begin() Lane.FullMulScope {
    return Lane.FullMulScope.init(emit);
}

const std = @import("std");
const Core = @import("stwo_core");
fn graph(a: std.mem.Allocator, native: bool, trace_only: bool) !Common.PoseidonContext {
    var structural = Lane.StructuralScope.init();
    defer structural.deinit();
    var scope: ?Lane.FullMulScope = if (native) begin() else null;
    defer if (scope) |*s| s.deinit();
    var owner = if (trace_only) try Common.PoseidonContext.initTraceOnly(a, 2) else try Common.PoseidonContext.init(a, 2);
    errdefer owner.deinit();
    Common.begin(&owner);
    var active = true;
    defer if (active) Common.finish() catch {};
    const x = try Lane.Lane.guess(owner.algebra(), Core.fields.om31.OM31.fromM31Array(.{Core.fields.m31.M31.one()} ** 8));
    const y = try Lane.Lane.guess(owner.algebra(), Core.fields.om31.OM31.fromM31Array(.{Core.fields.m31.M31.fromCanonical(7)} ** 8));
    const z = x.mul(y);
    try Common.finish();
    active = false;
    try owner.setOutputs(&.{ z.c0.v, z.c1.v });
    try owner.finalize();
    return owner;
}
test "OP R6 native OM31 sidecar removes full product rows and keeps exact source fanout" {
    const a = std.testing.allocator;
    var control = try graph(a, false, false);
    defer control.deinit();
    var native = try graph(a, true, false);
    defer native.deinit();
    var trace = try graph(a, true, true);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 1), native.native_mul_calls.items.len);
    try std.testing.expectEqual(control.base.gate_counts.qm31_ops - 7, native.base.gate_counts.qm31_ops);
    try std.testing.expectEqualDeep(native.native_mul_calls.items, trace.native_mul_calls.items);
    try std.testing.expectEqualDeep(native.base.circuit.add.items, trace.base.circuit.add.items);
    try std.testing.expectEqualDeep(native.base.circuit.eq.items, trace.base.circuit.eq.items);
    try std.testing.expect(try native.isCircuitValid());
    const id = native.native_mul_calls.items[0].outputs[1];
    const saved = native.base.value_table.items[id];
    native.base.value_table.items[id] = saved.add(Core.fields.qm31.QM31.one());
    try std.testing.expect(!try native.isCircuitValid());
    native.base.value_table.items[id] = saved;
    // The legacy constructor cannot publish a five-component key for outputs
    // whose unique producer is the new sixth component.
    try std.testing.expectError(error.PoseidonMissingProducer, @import("../authority.zig").Authority.init(a, &native));
}
