//! Retain actual capacity and default exact Stream/receiver bodies. No worker,
//! source, file, commitment or proof is created by this object-only root.
const std = @import("std");
const core = @import("stwo_core");
const Stage = @import("prover/block_v5_capacity_open_forest_stage_v1.zig");
const Exact = @import("recursion/block_v5_capacity_exact_forest_receiver_v1.zig");
const DefaultStage = @import("prover/block_v5_open_forest_stage_v1.zig");
const DefaultExact = @import("recursion/block_v5_open_exact_forest_receiver_v1.zig");
const Manifest = @import("prover/block_v5_capacity_open_forest_manifest_v1.zig");
const DefaultManifest = @import("prover/block_v5_open_forest_manifest_v1.zig");
const Loader = struct {
    dir: std.fs.Dir,
    file: Exact.FilePin,
    max_bytes: usize,
    pub fn load(self: @This(), a: std.mem.Allocator) ![]u8 {
        return Stage.openPinned(a, self.dir, Stage.OUTER_FILE, self.file, self.max_bytes);
    }
};
fn start(a: std.mem.Allocator, dir: std.fs.Dir, pins: Exact.OuterPins, options: Stage.Options) anyerror!*Stage.Stream {
    return Stage.Stream.start(a, dir, pins, options);
}
fn submit(stream: *Stage.Stream, index: u32, leaf: Stage.LeafFile) anyerror!void {
    return stream.submit(index, leaf);
}
fn finish(stream: *Stage.Stream) anyerror!Stage.Stage {
    return stream.finish();
}
fn receive(a: std.mem.Allocator, loader: Loader, file: Exact.FilePin, leaves: []const Exact.LeafPolicy, parents: []const Exact.NodePin, outer: Exact.NodePin, pins: Exact.OuterPins, native_sum: core.fields.qm31.QM31, limits: Exact.Limits) anyerror!Exact.Verified {
    return Exact.verifyLoadedWithLimits(a, loader, file, leaves, parents, outer, pins, native_sum, limits);
}
fn defaultReceive(a: std.mem.Allocator, loader: Loader, file: DefaultExact.FilePin, leaves: []const DefaultExact.LeafPolicy, parents: []const DefaultExact.NodePin, outer: DefaultExact.NodePin, pins: DefaultExact.OuterPins, native_sum: core.fields.qm31.QM31, limits: DefaultExact.Limits) anyerror!DefaultExact.Verified {
    return DefaultExact.verifyLoadedWithLimits(a, loader, file, leaves, parents, outer, pins, native_sum, limits);
}
fn write(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const Stage.Stage, leaves: []const Stage.LeafFile, profile: @import("recursion/blake3_execution_parent_protocol.zig").Profile, limits: Manifest.Limits) anyerror![32]u8 {
    return Manifest.write(a, dir, staged, leaves, profile, limits);
}
fn detached(a: std.mem.Allocator, dir: std.fs.Dir, sha: [32]u8, leaves: []const Exact.LeafPolicy, parents: []const Exact.NodePin, outer: Exact.NodePin, file: Exact.FilePin, pins: Exact.OuterPins, sum: core.fields.qm31.QM31, limits: Manifest.Limits) anyerror!Exact.Verified {
    return Manifest.verifyDetachedPinned(a, dir, sha, leaves, parents, outer, file, pins, sum, limits);
}
fn defaultDetached(a: std.mem.Allocator, dir: std.fs.Dir, sha: [32]u8, leaves: []const DefaultExact.LeafPolicy, parents: []const DefaultExact.NodePin, outer: DefaultExact.NodePin, file: DefaultExact.FilePin, pins: DefaultExact.OuterPins, sum: core.fields.qm31.QM31, limits: DefaultManifest.Limits) anyerror!DefaultExact.Verified {
    return DefaultManifest.verifyDetachedPinned(a, dir, sha, leaves, parents, outer, file, pins, sum, limits);
}
export fn stwo_capacity_exact_body_gate() void {
    inline for (.{ &start, &submit, &finish, &Stage.Stream.abort, &Stage.Stage.deinit, &receive, &defaultReceive, &DefaultStage.Stream.start, &DefaultStage.Stream.submit, &DefaultStage.Stream.finish, &DefaultStage.Stream.abort, &write, &detached, &defaultDetached }) |function| std.mem.doNotOptimizeAway(function);
}
