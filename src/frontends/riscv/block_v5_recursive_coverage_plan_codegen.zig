//! Retain actual typed Global.Pins derivation bodies. No verifier, commitment,
//! guest execution or recursive proof is invoked by this codegen fixture.
const std = @import("std");
const Coverage = @import("prover/block_v5_recursive_coverage_plan_v1.zig");
const Stacks = @import("prover/block_v5_native_receiver_stack_v1.zig");
const Legacy = Stacks.ForCapacity(false);
const Capacity = Stacks.ForCapacity(true);
const LegacyGlobal = @import("prover/block_v5_global_receiver_impl_v1.zig").ForStack(Legacy);
const CapacityGlobal = @import("prover/block_v5_global_receiver_impl_v1.zig").ForStack(Capacity);
fn legacy(a: std.mem.Allocator, pins: LegacyGlobal.Pins, security: Coverage.Security, limits: Coverage.Limits) anyerror!Coverage.Plan {
    return Coverage.ForStack(Legacy).prepare(a, pins, security, .quartet, limits);
}
fn capacity(a: std.mem.Allocator, pins: CapacityGlobal.Pins, security: Coverage.Security, limits: Coverage.Limits) anyerror!Coverage.Plan {
    return Coverage.ForStack(Capacity).prepare(a, pins, security, .quartet, limits);
}
pub fn retain() void {
    inline for (.{ &legacy, &capacity, &Coverage.Plan.deinit, &Coverage.Plan.requireExact }) |body| std.mem.doNotOptimizeAway(body);
}

test "coverage bodies: actual typed global inventory derivation retained without proof invocation" {
    retain();
}
