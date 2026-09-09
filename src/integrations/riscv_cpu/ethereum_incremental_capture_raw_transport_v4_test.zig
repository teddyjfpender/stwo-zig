const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const capture = @import("ethereum_incremental_capture_publication_v4.zig");
const raw = @import("ethereum_incremental_capture_raw_transport_v4.zig");
const leaf_support = @import("ethereum_block_leaf_support.zig");
const support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

const minimal = frontend.runner.minimal_trace;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;

test "early V4 owner publishes raw pair and cold-adopts exact restart" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const fixture = try support.Fixture.init();
    var global_source = fixture.leftSource();
    global_source.session_id = leaf_support.sessionDigest(
        try execution().sessionIdentity(),
    );
    const retained = retainedMetadata(global_source);
    const source = try localSource(global_source, &retained);
    var wire = try support.OwnedWire.init(allocator, &source);
    defer wire.deinit();
    const compact = try compactBytes(allocator, source);
    defer allocator.free(compact);

    var first = try raw.EarlyRawOwnerV4.initExisting(
        allocator,
        root,
        execution(),
    );
    errdefer first.deinit();
    const published = try first.publishOrCompareLive(
        0,
        compact,
        &wire.data,
        &retained,
    );
    try published.validate();
    try std.testing.expectEqual(@as(u32, 1), first.publishedCount());
    first.deinit();

    var resumed = try raw.EarlyRawOwnerV4.initExisting(
        allocator,
        root,
        execution(),
    );
    defer resumed.deinit();
    const adopted = try resumed.publishOrCompareLive(
        0,
        compact,
        &wire.data,
        &retained,
    );
    try std.testing.expectEqual(published, adopted);
    try std.testing.expect(!raw.PRODUCTION_ACTIVE);
    try std.testing.expect(raw.PUBLIC_WIRE_REFERENCE_DEFERRED);
}

test "early V4 owner rejects order boundary and byte drift" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const fixture = try support.Fixture.init();
    var global_source = fixture.leftSource();
    global_source.session_id = leaf_support.sessionDigest(
        try execution().sessionIdentity(),
    );
    const retained = retainedMetadata(global_source);
    const source = try localSource(global_source, &retained);
    var wire = try support.OwnedWire.init(allocator, &source);
    defer wire.deinit();
    const compact = try compactBytes(allocator, source);
    defer allocator.free(compact);
    var owner = try raw.EarlyRawOwnerV4.initExisting(
        allocator,
        root,
        execution(),
    );
    errdefer owner.deinit();
    try std.testing.expectError(
        error.SegmentIndexMismatch,
        owner.publishOrCompareLive(1, compact, &wire.data, &retained),
    );
    _ = try owner.publishOrCompareLive(0, compact, &wire.data, &retained);
    owner.deinit();

    var restarted = try raw.EarlyRawOwnerV4.initExisting(
        allocator,
        root,
        execution(),
    );
    defer restarted.deinit();
    const changed = try allocator.dupe(u8, compact);
    defer allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try std.testing.expectError(
        error.ArtifactChecksumMismatch,
        restarted.publishOrCompareLive(0, changed, &wire.data, &retained),
    );
}

/// The retained STWESG31 base statement is globally positioned, while the
/// STWIPW04 wire authenticates the unique leaf-local V2 projection used by the
/// native prover.  Keeping those two authorities distinct is the contract the
/// early owner checks in production.
fn localSource(
    global_source: frontend.recursion.segment_statement_v2.SourceV2,
    retained: *const frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
) !frontend.recursion.segment_statement_v2.SourceV2 {
    var local = global_source;
    local.base_statement = try projection_v3.localStatementFromMetadata(retained);
    local.global_first_cycle = 1;
    try local.validate();
    return local;
}

fn retainedMetadata(
    source: frontend.recursion.segment_statement_v2.SourceV2,
) frontend.recursion.segment_leaf_local_authority_v3.MetadataV3 {
    const statement = source.statement() catch unreachable;
    const base = source.base_statement.canonicalWords() catch unreachable;
    return .{
        .base_statement_words = base,
        .segment_index = source.segment_index,
        .segment_count = source.base_statement.job.segment_count,
        .global_cycle_start = 0,
        .global_cycle_end = @intCast(source.cycle_count),
        .local_cycle_count = @intCast(source.cycle_count),
        .entry = .{
            .snapshot_id = statement.entry_snapshot_id,
            .snapshot_count = statement.entry_snapshot_count,
            .continuation_root = statement.entry_continuation_root,
            .register_clocks = statement.entry_register_clocks,
            .memory_clock_id = statement.entry_memory_clock_id,
            .memory_clock_count = statement.entry_memory_clock_count,
        },
        .exit = .{
            .snapshot_id = statement.exit_snapshot_id,
            .snapshot_count = statement.exit_snapshot_count,
            .continuation_root = statement.exit_continuation_root,
            .register_clocks = statement.exit_register_clocks,
            .memory_clock_id = statement.exit_memory_clock_id,
            .memory_clock_count = statement.exit_memory_clock_count,
        },
        .completion = statement.completion,
    };
}

fn compactBytes(
    allocator: std.mem.Allocator,
    source: frontend.recursion.segment_statement_v2.SourceV2,
) ![]u8 {
    const boundary = try minimal.SliceBoundary.init(&.{});
    const ordinary = try allocator.alloc(u32, 0);
    errdefer allocator.free(ordinary);
    const keccak = try allocator.alloc(minimal.ethereum_types.KeccakRecord, 0);
    errdefer allocator.free(keccak);
    const recovery = try allocator.alloc(
        minimal.ethereum_types.RecoveryRecord,
        0,
    );
    errdefer allocator.free(recovery);
    var leaf = try minimal.ethereum_types.LeafV1.initOwned(
        allocator,
        .{
            .program = [_]u8{1} ** 32,
            .input = [_]u8{2} ** 32,
            .session = [_]u8{3} ** 32,
            .entry_memory = [_]u8{4} ** 32,
            .exit_memory = [_]u8{5} ** 32,
        },
        boundary.entry_identity,
        boundary.exit_identity,
        0,
        source.global_first_cycle,
        @intCast(source.cycle_count),
        @intCast(source.cycle_count),
        source.entry_cpu,
        source.exit_cpu,
        null,
        ordinary,
        keccak,
        recovery,
    );
    defer leaf.deinit();
    return minimal.encodeEthereumMinimalArtifactAlloc(allocator, &.{
        .leaf = leaf,
        .boundary_words = &.{},
        .allocator = allocator,
    });
}

fn execution() capture.ExecutionAuthorityV4 {
    return .{
        .elf = identity(1),
        .input = identity(2),
        .expected_output = identity(3),
        .execution_profile_semantic_sha256 = [_]u8{4} ** 32,
        .segment_count = 2,
        .segment_step_budget = 100,
    };
}

fn identity(tag: u8) capture.ArtifactIdentityV4 {
    return .{ .byte_count = tag, .sha256 = [_]u8{tag} ** 32 };
}
