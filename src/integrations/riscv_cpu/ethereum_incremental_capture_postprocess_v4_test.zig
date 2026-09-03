const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const postprocess = @import("ethereum_incremental_capture_postprocess_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

const memory_state = frontend.runner.memory_state;
const minimal = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;

const Side = enum { left, right };
const left_input_words = [_]u32{11};

test "VM-free V4 owner mints sequential jobs then cold-publishes independently" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const fixture = try support.Fixture.init();
    const execution = executionAuthority();
    const initial = [_]@import("ethereum_incremental_boundary_authority_v1.zig").SparseWordV1{.{
        .address = 0x2000,
        .value = 11,
    }};
    const initial_root = try artifact_v2.testing.fullRoot(allocator, &initial);
    var owner = try postprocess.SequentialMintOwnerV4.init(
        allocator,
        execution,
        &initial,
        initial_root,
    );
    defer owner.deinit();

    var left_wire = try support.OwnedWire.init(allocator, &fixture.leftSource());
    defer left_wire.deinit();
    const left_metadata = try left_wire.data.metadata();
    const left_public = publicData(.left, left_metadata);
    const left_compact = try compactBytes(
        allocator,
        fixture.leftSource(),
        &.{.{ .address = 0x2000, .entry = 11, .exit = 12 }},
    );
    defer allocator.free(left_compact);
    const left_wire_bytes = try wire_publication.encodeWireAlloc(
        allocator,
        .{ .segment_index = 0, .segment_count = 2 },
        &left_wire.data,
    );
    defer allocator.free(left_wire_bytes);
    try publishRaw(allocator, root, 0, left_compact, left_wire_bytes);
    const left_touched = [_]@import("ethereum_incremental_boundary_authority_v1.zig").TouchedWordV1{.{
        .address = 0x2000,
        .old_word = 11,
        .new_word = 12,
        .final_clock = 3,
    }};
    var left_job = try owner.mint(.{
        .segment_index = 0,
        .compact_tape = publication.ArtifactIdentityV4.fromBytes(left_compact),
        .public_wire = publication.ArtifactIdentityV4.fromBytes(left_wire_bytes),
        .source = identity(31),
        .journal_record_sha256 = digest(41),
        .touched_words = &left_touched,
        .segment_public_wire = &left_wire.data,
        .public_authority = publicAuthority(
            .left,
            left_metadata,
            &left_public,
        ),
    });
    defer left_job.deinit();
    try left_job.validate();

    var right_wire = try support.OwnedWire.init(allocator, &fixture.rightSource());
    defer right_wire.deinit();
    const right_metadata = try right_wire.data.metadata();
    const right_public = publicData(.right, right_metadata);
    const right_compact = try compactBytes(
        allocator,
        fixture.rightSource(),
        &.{
            .{ .address = 0x2000, .entry = 12, .exit = 13 },
            .{ .address = 0x2004, .entry = 0, .exit = 9 },
        },
    );
    defer allocator.free(right_compact);
    const right_wire_bytes = try wire_publication.encodeWireAlloc(
        allocator,
        .{ .segment_index = 1, .segment_count = 2 },
        &right_wire.data,
    );
    defer allocator.free(right_wire_bytes);
    try publishRaw(allocator, root, 1, right_compact, right_wire_bytes);
    const right_touched = [_]@import("ethereum_incremental_boundary_authority_v1.zig").TouchedWordV1{
        .{ .address = 0x2000, .old_word = 12, .new_word = 13, .final_clock = 7 },
        .{ .address = 0x2004, .old_word = 0, .new_word = 9, .final_clock = 6 },
    };
    var right_job = try owner.mint(.{
        .segment_index = 1,
        .compact_tape = publication.ArtifactIdentityV4.fromBytes(right_compact),
        .public_wire = publication.ArtifactIdentityV4.fromBytes(right_wire_bytes),
        .source = identity(32),
        .journal_record_sha256 = digest(42),
        .touched_words = &right_touched,
        .segment_public_wire = &right_wire.data,
        .public_authority = publicAuthority(
            .right,
            right_metadata,
            &right_public,
        ),
    });
    defer right_job.deinit();
    try std.testing.expectEqual(@as(u32, 2), owner.mintedCount());

    left_job.artifact_bytes[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalColdJobV4,
        left_job.validate(),
    );
    left_job.artifact_bytes[0] ^= 1;
    try left_job.validate();

    // These calls share no mutable chain state and may be run by a bounded
    // worker pool. The test intentionally completes the right job first.
    const retained_right = retainedMetadata(fixture.rightSource());
    const right_result = try postprocess.coldVerifyAndPublish(
        allocator,
        root,
        &right_job,
        &right_wire.data,
        publicAuthority(.right, right_metadata, &right_public),
        &retained_right,
    );
    const retained_left = retainedMetadata(fixture.leftSource());
    const left_result = try postprocess.coldVerifyAndPublish(
        allocator,
        root,
        &left_job,
        &left_wire.data,
        publicAuthority(.left, left_metadata, &left_public),
        &retained_left,
    );
    const wrong = [_]postprocess.ColdResultV4{ right_result, left_result };
    try std.testing.expectError(
        error.IncrementalPostprocessColdResultMismatchV4,
        owner.sealAfterCold(root, finalBindings(), &wrong),
    );
    const ordered = [_]postprocess.ColdResultV4{ left_result, right_result };
    var sealed = try owner.sealAfterCold(root, finalBindings(), &ordered);
    defer sealed.deinit();
    try std.testing.expectEqual(@as(u32, 2), sealed.transition.value.segment_count);
    try std.testing.expectEqual(@as(u32, 2), sealed.public_wire.value.segment_count);
    try std.testing.expect(postprocess.COLD_JOBS_PARALLELIZABLE);
    try std.testing.expect(!postprocess.PRODUCTION_ACTIVE);
}

fn retainedMetadata(
    source: frontend.recursion.segment_statement_v2.SourceV2,
) frontend.recursion.segment_leaf_local_authority_v3.MetadataV3 {
    const statement = source.statement() catch unreachable;
    const base = source.base_statement.canonicalWords() catch unreachable;
    const reset_clocks = [_]u32{0} ** 32;
    const empty_memory_clock_id = frontend.recursion.segment_statement_v2
        .memoryClockIdentity(&.{});
    return .{
        .base_statement_words = base,
        .segment_index = source.segment_index,
        .segment_count = source.base_statement.job.segment_count,
        .global_cycle_start = source.global_first_cycle - 1,
        .global_cycle_end = source.global_first_cycle - 1 + source.cycle_count,
        .local_cycle_count = @intCast(source.cycle_count),
        .entry = .{
            .snapshot_id = statement.entry_snapshot_id,
            .snapshot_count = statement.entry_snapshot_count,
            .continuation_root = statement.entry_continuation_root,
            .register_clocks = reset_clocks,
            .memory_clock_id = empty_memory_clock_id,
            .memory_clock_count = 0,
        },
        .exit = .{
            .snapshot_id = statement.exit_snapshot_id,
            .snapshot_count = statement.exit_snapshot_count,
            .continuation_root = statement.exit_continuation_root,
            .register_clocks = reset_clocks,
            .memory_clock_id = empty_memory_clock_id,
            .memory_clock_count = 0,
        },
        .completion = statement.completion,
    };
}

test "sequential mint order failure poisons the process-local owner" {
    const allocator = std.testing.allocator;
    const initial = [_]@import("ethereum_incremental_boundary_authority_v1.zig").SparseWordV1{.{
        .address = 0x2000,
        .value = 11,
    }};
    const initial_root = try artifact_v2.testing.fullRoot(allocator, &initial);
    var owner = try postprocess.SequentialMintOwnerV4.init(
        allocator,
        executionAuthority(),
        &initial,
        initial_root,
    );
    defer owner.deinit();
    const fixture = try support.Fixture.init();
    var wire = try support.OwnedWire.init(allocator, &fixture.rightSource());
    defer wire.deinit();
    const metadata = try wire.data.metadata();
    const value = publicData(.right, metadata);
    const touched = [_]@import("ethereum_incremental_boundary_authority_v1.zig").TouchedWordV1{
        .{ .address = 0x2000, .old_word = 12, .new_word = 13, .final_clock = 7 },
    };
    const input = postprocess.MintInputV4{
        .segment_index = 1,
        .compact_tape = identity(21),
        .public_wire = identity(22),
        .source = identity(23),
        .journal_record_sha256 = digest(24),
        .touched_words = &touched,
        .segment_public_wire = &wire.data,
        .public_authority = publicAuthority(.right, metadata, &value),
    };
    try std.testing.expectError(
        error.InvalidIncrementalPostprocessInputV4,
        owner.mint(input),
    );
    try std.testing.expectError(
        error.IncrementalPostprocessOwnerPoisonedV4,
        owner.mint(input),
    );
}

fn publishRaw(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
    compact: []const u8,
    wire: []const u8,
) !void {
    const compact_path = try publication.compactTapePathAlloc(
        allocator,
        root,
        index,
    );
    defer allocator.free(compact_path);
    try artifact_io.publishCreateOnlyDurable(compact_path, compact);
    const wire_path = try wire_publication.wirePathAlloc(allocator, root, index);
    defer allocator.free(wire_path);
    try artifact_io.publishCreateOnlyDurable(wire_path, wire);
}

fn compactBytes(
    allocator: std.mem.Allocator,
    source: frontend.recursion.segment_statement_v2.SourceV2,
    boundary_words: []const minimal.BoundaryWord,
) ![]u8 {
    const boundary = try minimal.SliceBoundary.init(boundary_words);
    const ordinary = try allocator.alloc(u32, 0);
    errdefer allocator.free(ordinary);
    const keccak = try allocator.alloc(minimal.ethereum_types.KeccakRecord, 0);
    errdefer allocator.free(keccak);
    const recovery = try allocator.alloc(
        minimal.ethereum_types.RecoveryRecord,
        0,
    );
    errdefer allocator.free(recovery);
    const completion: ?minimal.ethereum_types.CompletionV1 = if (source.completion) |value|
        .{
            .kind = switch (value.kind) {
                .halt_flag => 1,
                .unretired_self_loop => 2,
            },
            .address = value.address,
            .value = value.value,
            .clock = value.clock,
        }
    else
        null;
    var leaf = try minimal.ethereum_types.LeafV1.initOwned(
        allocator,
        .{
            .program = digest(1),
            .input = digest(2),
            .session = digest(3),
            .entry_memory = digest(4),
            .exit_memory = digest(5),
        },
        boundary.entry_identity,
        boundary.exit_identity,
        source.segment_index,
        source.global_first_cycle,
        @intCast(source.cycle_count),
        @intCast(source.cycle_count),
        source.entry_cpu,
        source.exit_cpu,
        completion,
        ordinary,
        keccak,
        recovery,
    );
    defer leaf.deinit();
    return minimal.encodeEthereumMinimalArtifactAlloc(allocator, &.{
        .leaf = leaf,
        .boundary_words = @constCast(boundary_words),
        .allocator = allocator,
    });
}

fn publicAuthority(
    side: Side,
    metadata: frontend.air.public_data_v2.Metadata,
    value: *const public_data.PublicData,
) boundary_v4.SegmentPublicAuthorityV4 {
    return .{
        .coordinate = .{
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
        },
        .segment_role = .{
            .is_first = metadata.is_first,
            .is_last = metadata.is_final,
        },
        .layout = layout(side),
        .public_data = value,
        .continuation_roots = .{
            .entry = metadata.entry_continuation_root,
            .exit = metadata.exit_continuation_root,
        },
    };
}

fn publicData(
    side: Side,
    metadata: frontend.air.public_data_v2.Metadata,
) public_data.PublicData {
    const completion: public_data.Completion = if (metadata.completion) |value|
        .{
            .kind = @enumFromInt(@intFromEnum(value.kind)),
            .address = value.address,
            .value = value.value,
            .clock = value.clock,
        }
    else
        public_data.Completion.canonicalSelfLoop(metadata.exit_cpu.pc);
    return .{
        .initial_pc = metadata.entry_cpu.pc,
        .final_pc = metadata.exit_cpu.pc,
        .clock = metadata.global_cycle_end - metadata.global_cycle_start,
        .initial_regs = metadata.entry_cpu.registers,
        .final_regs = metadata.exit_cpu.registers,
        .reg_last_clock = metadata.exit_cpu.predecessor_clocks,
        .program_root = metadata.program[0],
        .initial_rw_root = metadata.entry_continuation_root,
        .final_rw_root = metadata.exit_continuation_root,
        .completion = completion,
        .io_entries = switch (side) {
            .left => .{
                .input_start = 0x2000,
                .input_len = 4,
                .input_words = &left_input_words,
                .output_len = 0,
                .output_len_addr = 0x2100,
                .output_data_addr = 0x2104,
                .output_words = &.{},
            },
            .right => .{
                .input_start = 0x2080,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0x2100,
                .output_data_addr = 0x2104,
                .output_words = &.{},
            },
        },
    };
}

fn layout(side: Side) memory_state.MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x2200,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x2000,
        .io_end = 0x2200,
        .input_base = if (side == .left) 0x2000 else 0x2080,
        .input_end = if (side == .left) 0x2004 else 0x2080,
        .output_len_addr = 0x2100,
        .output_data_addr = 0x2104,
        .output_base = 0x2100,
        .output_end = 0x2200,
    };
}

fn executionAuthority() publication.ExecutionAuthorityV4 {
    return .{
        .elf = identity(1),
        .input = identity(2),
        .expected_output = identity(3),
        .execution_profile_semantic_sha256 = digest(4),
        .segment_count = 2,
        .segment_step_budget = 100,
    };
}

fn finalBindings() publication.FinalBindingsV4 {
    return .{
        .compact_manifest = identity(11),
        .materialization_result = identity(12),
        .source_request = identity(13),
        .journal = identity(14),
        .execution_profile_receipt = identity(15),
    };
}

fn identity(tag: u8) publication.ArtifactIdentityV4 {
    return .{ .byte_count = tag, .sha256 = digest(tag) };
}

fn digest(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
}
