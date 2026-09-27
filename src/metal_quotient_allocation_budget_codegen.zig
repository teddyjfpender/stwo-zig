//! Compile real quotient dispatch bodies; never execute these wrappers.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const runtime = @import("backends/metal/runtime.zig");
const ops = @import("backends/metal/runtime/polynomial_operations.zig");
const Provider = engine.pcs.quotient_ops.LazyQuotientProvider;
const Column = engine.secure_column.SecureColumnByCoords;
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
const Blake3 = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher;

fn blake3Lazy(a: std.mem.Allocator, provider: *Provider, output: *Column) anyerror!Backend.MerkleTree(Blake3) {
    return Backend.commitLazyMerkle(Blake3, a, provider, output);
}

fn bare(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column) anyerror!void {
    _ = try ops.computeQuotients(metal, a, provider, output);
}
fn bareProfiled(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column) anyerror!void {
    _ = try ops.computeQuotientsWithReceipt(metal, a, provider, output);
}
fn committed(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column, family: u32, seeds: [2][8]u32, prefix: u32) anyerror!runtime.QuotientCommitResult {
    return ops.computeQuotientsAndCommitForHash(metal, a, provider, output, seeds[0], seeds[1], prefix, family);
}
fn committedProfiled(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column, family: u32, seeds: [2][8]u32, prefix: u32) anyerror!void {
    var result = try ops.computeQuotientsAndCommitWithReceiptForHash(metal, a, provider, output, seeds[0], seeds[1], prefix, family);
    result.tree.deinit();
}
fn fused(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column, line_output: *anyopaque, coordinates: []const *anyopaque, terminal: *anyopaque, initial: u32, step: u32, channel: *[11]u32) anyerror!runtime.QuotientFriCommitResult {
    return ops.computeQuotientsAndCommitFri(metal, true, a, provider, output, line_output, coordinates, terminal, initial, step, channel, @splat(0), @splat(0), 0);
}
fn fusedProfiled(a: std.mem.Allocator, metal: *runtime.Runtime, provider: *Provider, output: *Column, line_output: *anyopaque, coordinates: []const *anyopaque, terminal: *anyopaque, initial: u32, step: u32, channel: *[11]u32) anyerror!void {
    var result = try ops.computeQuotientsAndCommitFriWithReceipt(metal, true, a, provider, output, line_output, coordinates, terminal, initial, step, channel, @splat(0), @splat(0), 0);
    result.tree.deinit();
    for (result.fri.trees) |*tree| tree.deinit();
    a.free(result.fri.trees);
}
const WorkRecorder = @import("stwo_prover_api").work_profile.Recorder(true);
const Blake3Domain = @import("stwo_core").vcs_lifted.blake3_merkle;
const Fri = engine.fri.FriProver(Backend, Blake3, Blake3Domain.MerkleChannel);
fn engineLazy(a: std.mem.Allocator, provider: *Provider, channel: *@import("stwo_core").channel.blake3.Channel, config: @import("stwo_core").fri.FriConfig, domain: @import("stwo_core").poly.circle.domain.CircleDomain, recorder: ?*WorkRecorder) anyerror!Fri {
    return Fri.commitLazyWithWorkRecorder(a, channel, config, domain, provider, recorder);
}
export fn stwo_metal_quotient_allocation_body_gate() void {
    std.mem.doNotOptimizeAway(&engineLazy);
    std.mem.doNotOptimizeAway(&blake3Lazy);
    std.mem.doNotOptimizeAway(&bare);
    std.mem.doNotOptimizeAway(&bareProfiled);
    std.mem.doNotOptimizeAway(&committed);
    std.mem.doNotOptimizeAway(&committedProfiled);
    std.mem.doNotOptimizeAway(&fused);
    std.mem.doNotOptimizeAway(&fusedProfiled);
}
