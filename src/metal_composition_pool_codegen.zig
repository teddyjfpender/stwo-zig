//! Real production source bodies compiled into an object, never executed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runtime = @import("backends/metal/runtime.zig");
const scratch = @import("backends/metal/runtime/composition_domain_scratch.zig");
const backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
fn acquire(a: std.mem.Allocator, metal: *runtime.Runtime, bytes: usize) anyerror!runtime.ResidentBuffer {
    return scratch.acquireResident(a, metal, bytes);
}
fn fresh(a: std.mem.Allocator, metal: *runtime.Runtime, bytes: usize) anyerror!runtime.ResidentBuffer {
    return scratch.allocateUnpooledResident(a, metal, bytes);
}
fn prepare(a: std.mem.Allocator, metal: *runtime.Runtime, trace: *const engine.air.component_prover.Trace, requests: []const scratch.RequestV1, twiddles: engine.poly.twiddles.TwiddleTree([]const core.fields.m31.M31)) anyerror!scratch.OwnedV1 {
    return scratch.OwnedV1.init(a, metal, trace, requests, twiddles);
}
fn leaves(a: std.mem.Allocator, columns: []const []const core.fields.m31.M31) anyerror!?engine.vcs_lifted.prover.MerkleProverLifted(core.vcs_lifted.blake3_merkle.MerkleHasher) {
    return @import("backends/metal/runtime/blake3_streaming_leaves.zig").tryCommit(core.vcs_lifted.blake3_merkle.MerkleHasher, a, columns);
}
fn destroy(value: *scratch.OwnedV1) void {
    value.deinit();
}
export fn stwo_metal_composition_pool_body_gate() void {
    std.mem.doNotOptimizeAway(&acquire);
    std.mem.doNotOptimizeAway(&fresh);
    std.mem.doNotOptimizeAway(&prepare);
    std.mem.doNotOptimizeAway(&leaves);
    std.mem.doNotOptimizeAway(&destroy);
    std.mem.doNotOptimizeAway(&backend.shutdown);
}
