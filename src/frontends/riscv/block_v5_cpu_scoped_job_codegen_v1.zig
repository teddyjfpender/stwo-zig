//! Actual new driver, original-family normalization/fresh capture and parent
//! publisher/detached reconstruction bodies retained, never called by marker.
const std = @import("std");
const Sources = @import("prover/block_v5_cpu_scoped_job_sources_v1.zig");
const Fold = @import("prover/block_v5_cpu_scoped_job_fold_v1.zig");
const Setup = @import("recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn deriveAndPublish(a: std.mem.Allocator, dir: std.fs.Dir, source: *const Sources.Owner, profile: @import("recursion/blake3_execution_parent_protocol.zig").Profile, limits: Fold.Limits, action: Fold.Action) anyerror!void {
    var result = try Fold.ForBackend(Cpu).run(a, dir, source, profile, limits, action);
    defer result.deinit();
}
fn finish(a: std.mem.Allocator, full: @import("recursion/block_v5_heterogeneous_policy_v1.zig").Policy, pins: Setup.Pins, specs: []const Setup.NodeSpec, limits: Setup.Limits) anyerror!void {
    var original = try Setup.init(a, full, pins, specs, limits);
    defer original.deinit();
    var setup = try Setup.prepareJob(a, full, .{ .job = pins.job, .coverage = pins.coverage, .source = pins.source, .recipe = pins.recipe }, limits);
    defer setup.deinit();
    var transferred = try setup.finish(pins, specs);
    defer transferred.deinit();
}
pub export fn stwo_cpu_scoped_job_body_gate() void {
    @import("block_v5_cpu_capacity_driver_codegen.zig").stwo_capacity_cpu_driver_body_gate();
    inline for (.{ &Sources.create, &Sources.Owner.readLeaf, &Sources.Owner.deinit, &deriveAndPublish, &finish, &@import("prover/block_v5_cpu_scoped_job_v1.zig").publish, &@import("prover/block_v5_cpu_scoped_job_receive_v1.zig").verify, &@import("prover/block_v5_cpu_scoped_job_receive_v1.zig").Received.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
