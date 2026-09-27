//! Actual generic PCS -> Metal LDE batch bodies; never execute these wrappers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
const runtime = @import("backends/metal/runtime.zig");
const B3 = core.vcs_lifted.blake3_merkle;
const Pcs = engine.pcs.CommitmentSchemeProver(Backend, B3.MerkleHasher, B3.MerkleChannel);
const M31 = core.fields.m31.M31;

fn commit(a: std.mem.Allocator, pcs: *Pcs, columns: []engine.pcs.ColumnEvaluation, channel: *core.channel.blake3.Channel) anyerror!void {
    try pcs.commitOwned(a, columns, channel);
}
fn begin(a: std.mem.Allocator) anyerror!Backend.CircleLdeBatch {
    return Backend.CircleLdeBatch.initWithAllocator(a);
}
fn finish(value: *Backend.CircleLdeBatch) anyerror!void {
    try value.finish();
}
fn destroy(value: *Backend.CircleLdeBatch) void {
    value.deinit();
}
fn lde(metal: *runtime.Runtime, a: std.mem.Allocator, batch: *runtime.CircleLdeBatch, sources: []const []const M31, coefficients: []const []M31, evaluations: []const []M31, arena: []M31, start: usize, stride: usize, inverse: []const M31, forward: []const M31, base_log: u32, extended_log: u32) anyerror!void {
    _ = try metal.transformCircleLdeIntoBatch(batch, a, sources, coefficients, evaluations, arena, start, stride, inverse, forward, base_log, extended_log);
}
fn standalone(metal: *runtime.Runtime, a: std.mem.Allocator, sources: []const []const M31, coefficients: []const []M31, evaluations: []const []M31, arena: []M31, start: usize, stride: usize, inverse: []const M31, forward: []const M31, base_log: u32, extended_log: u32) anyerror!void {
    _ = try metal.transformCircleLdeInto(a, sources, coefficients, evaluations, arena, start, stride, inverse, forward, base_log, extended_log);
}
export fn stwo_metal_circle_lde_budget_body_gate() void {
    std.mem.doNotOptimizeAway(&commit);
    std.mem.doNotOptimizeAway(&begin);
    std.mem.doNotOptimizeAway(&finish);
    std.mem.doNotOptimizeAway(&destroy);
    std.mem.doNotOptimizeAway(&lde);
    std.mem.doNotOptimizeAway(&standalone);
}
