const std = @import("std");
const fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const pcs = @import("stwo_core").pcs;
const host_merkle = @import("stwo_prover_impl").vcs_lifted.prover;
const proof_wire = @import("../../../interop/proof_wire/mod.zig");
const wide_fibonacci = @import("../../../examples/wide_fibonacci.zig");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const MetalBackend = @import("stwo_metal_backend").commit_backend.MetalCommitBackend;
const MetalTree = @import("stwo_metal_backend").merkle_tree.MetalMerkleTree(wide_fibonacci.Hasher);
const shared_runtime = @import("stwo_metal_backend").shared_runtime;

const M31 = m31.M31;

const ProofThreadResult = struct {
    failure: ?anyerror = null,
    digest: [32]u8 = [_]u8{0} ** 32,
};

fn proofDigest(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    statement: wide_fibonacci.Statement,
) ![32]u8 {
    var output = try wide_fibonacci.proveWithBackend(
        Backend,
        allocator,
        config,
        statement,
        null,
    );
    var proof_owned = true;
    errdefer if (proof_owned) output.proof.deinit(allocator);

    const bytes = try proof_wire.encodeProofBytes(allocator, output.proof);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});

    proof_owned = false;
    try wide_fibonacci.verify(allocator, config, output.statement, output.proof);
    return digest;
}

fn proofThread(
    result: *ProofThreadResult,
    config: pcs.PcsConfig,
    statement: wide_fibonacci.Statement,
) void {
    result.digest = proofDigest(MetalBackend, std.heap.smp_allocator, config, statement) catch |err| {
        result.failure = err;
        return;
    };
}

test "metal: simultaneous proofs use isolated explicit residency sets" {
    const was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!was_initialized) MetalBackend.shutdown() catch unreachable;

    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
    // The raw trace is exactly 64 MiB after blowup, forcing resident quotient
    // reuse rather than the small-input upload path.
    const statement = wide_fibonacci.Statement{
        .log_n_rows = 17,
        .sequence_len = 64,
    };
    var first: ProofThreadResult = .{};
    var second: ProofThreadResult = .{};
    const first_thread = try std.Thread.spawn(.{}, proofThread, .{ &first, config, statement });
    const second_thread = try std.Thread.spawn(.{}, proofThread, .{ &second, config, statement });
    first_thread.join();
    second_thread.join();

    if (first.failure) |err| return err;
    if (second.failure) |err| return err;
    try std.testing.expectEqualSlices(u8, &first.digest, &second.digest);
    const cpu_digest = try proofDigest(CpuBackend, std.heap.smp_allocator, config, statement);
    try std.testing.expectEqualSlices(u8, &cpu_digest, &first.digest);
    try std.testing.expectEqual(@as(u64, 0), MetalBackend.runtimeLifecycleSnapshot().active_call_leases);
}

test "metal: resident tree lifetime survives reuse and blocks runtime destruction" {
    const allocator = std.testing.allocator;
    try MetalBackend.initializeRuntime(allocator, .source_jit);
    defer {
        if (MetalBackend.runtimeLifecycleSnapshot().initialized)
            MetalBackend.shutdown() catch unreachable;
    }

    const row_count: usize = 1 << 10;
    const storage = try std.heap.page_allocator.alloc(u8, row_count * 2 * @sizeOf(M31));
    defer std.heap.page_allocator.free(storage);
    var reuse_arena = std.heap.FixedBufferAllocator.init(storage);
    const reuse_allocator = reuse_arena.allocator();
    var backing = try reuse_allocator.alloc(M31, row_count * 2);
    const original_address = @intFromPtr(backing.ptr);
    const first_columns = [_][]const M31{
        backing[0..row_count],
        backing[row_count .. row_count * 2],
    };
    for (backing, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index + 1));

    var first_tree = blk: {
        var lease = try shared_runtime.acquireExisting();
        defer lease.deinit();
        break :blk try MetalTree.commitSharedBacking(lease.runtime, allocator, &first_columns, backing);
    };
    const first_root = first_tree.root();
    try std.testing.expect(first_tree.quotientResidencyHandle() != null);
    first_tree.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), MetalBackend.runtimeLifecycleSnapshot().live_resident_resources);

    // Free and reallocate from a page-backed allocator so the new proof
    // session receives the exact old address. No stale runtime registry may
    // match it to the destroyed owner.
    reuse_allocator.free(backing);
    backing = try reuse_allocator.alloc(M31, row_count * 2);
    defer reuse_allocator.free(backing);
    try std.testing.expectEqual(original_address, @intFromPtr(backing.ptr));
    const reused_columns = [_][]const M31{
        backing[0..row_count],
        backing[row_count .. row_count * 2],
    };
    for (backing, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index + 17));
    var resident_tree = blk: {
        var lease = try shared_runtime.acquireExisting();
        defer lease.deinit();
        break :blk try MetalTree.commitSharedBacking(lease.runtime, allocator, &reused_columns, backing);
    };
    var resident_tree_live = true;
    defer if (resident_tree_live) resident_tree.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, &first_root, &resident_tree.root()));

    var host_tree = MetalTree.fromHost(try host_merkle.MerkleProverLifted(
        wide_fibonacci.Hasher,
    ).commit(allocator, &reused_columns));
    var host_tree_live = true;
    defer if (host_tree_live) host_tree.deinit(allocator);
    try std.testing.expect(host_tree.quotientResidencyHandle() == null);
    try std.testing.expect(resident_tree.quotientResidencyHandle() != null);

    try std.testing.expectError(error.ResidentResourcesLive, MetalBackend.shutdown());
    resident_tree.deinit(allocator);
    resident_tree_live = false;
    host_tree.deinit(allocator);
    host_tree_live = false;
    try MetalBackend.shutdown();
    try std.testing.expect(!MetalBackend.runtimeLifecycleSnapshot().initialized);
}

test "metal: failure after combined commitment ownership transfer releases the arena" {
    const was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!was_initialized) MetalBackend.shutdown() catch unreachable;
    const resources_before = MetalBackend.runtimeLifecycleSnapshot().live_resident_resources;

    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
    MetalBackend.armOwnershipTransferFailureForTesting();
    defer MetalBackend.clearOwnershipTransferFailureForTesting();
    try std.testing.expectError(
        error.InjectedOwnershipTransferFailure,
        wide_fibonacci.proveWithBackend(
            MetalBackend,
            std.testing.allocator,
            config,
            .{ .log_n_rows = 16, .sequence_len = 64 },
            null,
        ),
    );
    try std.testing.expectEqual(
        resources_before,
        MetalBackend.runtimeLifecycleSnapshot().live_resident_resources,
    );
}

test "metal: quotient residency has no runtime-wide discovery surface" {
    const source_contract = @import("stwo_metal_backend").source_contract;
    const runtime_source = source_contract.runtime;
    const quotient_source = source_contract.quotients;
    try std.testing.expect(std.mem.indexOf(u8, runtime_source, "residentTraceTrees") == null);
    try std.testing.expect(std.mem.indexOf(u8, runtime_source, "compositionTraceBuffer") == null);
    try std.testing.expect(std.mem.indexOf(u8, quotient_source, "resident_tree_handles") != null);
    try std.testing.expect(std.mem.indexOf(u8, quotient_source, "runtimeOwner != runtime") != null);
    const composition_source = source_contract.composition;
    try std.testing.expect(std.mem.indexOf(u8, composition_source, "resident_tree_handle") != null);
    try std.testing.expect(std.mem.indexOf(u8, composition_source, "runtimeOwner != runtime") != null);
}
