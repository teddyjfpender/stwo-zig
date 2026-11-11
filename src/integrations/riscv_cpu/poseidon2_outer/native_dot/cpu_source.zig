//! Actual CPU leaf source factory for R7. No native proof/root route is switched.
//! The full CPU verifier emitter is shared with the unchanged R5/R6 factories.
const std = @import("std");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Phase = @import("../phase_census.zig");
pub fn build(a: std.mem.Allocator, source: CPU.ShapeView, trace_only: bool, census: ?*CPU.CompleteCounts) !C.PoseidonContext {
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
    errdefer owner.deinit();
    var mul = @import("../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot = @import("scope.zig").Scope.begin(&owner);
    defer dot.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    var emitted = try source.emitInto(&owner, census);
    defer emitted.deinit(ctx);
    if (!trace_only) for (emitted.output, try source.expectedOutput(a)) |port, value| {
        if (!ctx.get(port).eql(value)) return error.R7CpuSourceOutputMismatch;
    };
    try C.finish();
    active = false;
    const before = Phase.Counts.take(&owner);
    try owner.setOutputs(&emitted.output);
    try owner.finalizeForNativeDot();
    if (census) |counts| counts.finalization = Phase.Counts.take(&owner).sub(before);
    if (ctx.circuit.blake_g_gate.items.len != 0 or ctx.circuit.triple_xor.items.len != 0) return error.UnsupportedR7CpuSourceOperation;
    return owner;
}
