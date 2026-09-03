const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v3_support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const capture_mod = @import("ethereum_incremental_boundary_capture_v2.zig");
const options = @import("ethereum_incremental_capture_materializer_options_v3.zig");
const publication = @import("ethereum_incremental_capture_publication_v3.zig");
const owner_mod =
    @import("ethereum_incremental_capture_publication_owner_v3.zig");

const memory_state = frontend.runner.memory_state;
const minimal = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;

const Side = enum { left, right };
const left_input_words = [_]u32{11};

test "V3 publication reexecutes and cold-adopts a durable prefix" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const fixture = try artifact_v3_support.Fixture.init();
    const execution = executionAuthority(2);
    const session_identity = try execution.sessionIdentity();
    const left_entry = try artifact_v2.testing.fullRoot(
        allocator,
        &.{.{ .address = 0x2000, .value = 11 }},
    );
    const left_exit = try artifact_v2.testing.fullRoot(
        allocator,
        &.{.{ .address = 0x2000, .value = 12 }},
    );
    const right_exit = try artifact_v2.testing.fullRoot(
        allocator,
        &.{
            .{ .address = 0x2000, .value = 13 },
            .{ .address = 0x2004, .value = 9 },
        },
    );
    try std.testing.expectEqual(left_entry, (try fixture.leftSource().statement()).entry_continuation_root);
    try std.testing.expectEqual(left_exit, (try fixture.leftSource().statement()).exit_continuation_root);
    try std.testing.expectEqual(right_exit, (try fixture.rightSource().statement()).exit_continuation_root);

    var first_capture = try capture_mod.SessionCaptureV2.init(
        allocator,
        session_identity,
        0,
        &snapshot(.left, &fixture.left_words),
        left_entry,
    );
    defer first_capture.deinit();
    var first_owner = try owner_mod.PublicationOwnerV3.initExisting(
        allocator,
        root,
        &first_capture,
        execution,
    );
    const left_compact = try compactBytes(
        allocator,
        0,
        fixture.leftSource(),
    );
    defer allocator.free(left_compact);
    var left_wire = try artifact_v3_support.OwnedWire.init(
        allocator,
        &fixture.leftSource(),
    );
    defer left_wire.deinit();
    const left_metadata = try left_wire.data.metadata();
    const left_public = publicData(.left, left_metadata);
    _ = try first_owner.captureAndPublish(
        0,
        &snapshot(.left, &fixture.left_words),
        &.{0x2000},
        left_entry,
        left_exit,
        left_compact,
        identity(0x31),
        [_]u8{0x41} ** 32,
        &left_wire.data,
        publicAuthority(.left, left_metadata, &left_public),
    );
    first_owner.deinit();

    // A new process-local capture starts at segment zero. Existing bytes are
    // adopted only after the live transition is recomputed and cold-opened.
    var resumed_capture = try capture_mod.SessionCaptureV2.init(
        allocator,
        session_identity,
        0,
        &snapshot(.left, &fixture.left_words),
        left_entry,
    );
    defer resumed_capture.deinit();
    var owner = try owner_mod.PublicationOwnerV3.initExisting(
        allocator,
        root,
        &resumed_capture,
        execution,
    );
    defer owner.deinit();
    _ = try owner.captureAndPublish(
        0,
        &snapshot(.left, &fixture.left_words),
        &.{0x2000},
        left_entry,
        left_exit,
        left_compact,
        identity(0x31),
        [_]u8{0x41} ** 32,
        &left_wire.data,
        publicAuthority(.left, left_metadata, &left_public),
    );

    const right_source = fixture.rightSource();
    const right_compact = try compactBytes(allocator, 1, right_source);
    defer allocator.free(right_compact);
    var right_wire = try artifact_v3_support.OwnedWire.init(
        allocator,
        &right_source,
    );
    defer right_wire.deinit();
    const right_metadata = try right_wire.data.metadata();
    const right_public = publicData(.right, right_metadata);
    _ = try owner.captureAndPublish(
        1,
        &snapshot(.right, &fixture.right_words),
        &.{ 0x2000, 0x2004 },
        left_exit,
        right_exit,
        right_compact,
        identity(0x32),
        [_]u8{0x42} ** 32,
        &right_wire.data,
        publicAuthority(.right, right_metadata, &right_public),
    );
    var manifest = try owner.finalize(finalBindings());
    defer manifest.deinit();
    try std.testing.expectEqual(@as(u32, 2), manifest.value.segment_count);
    try std.testing.expectEqual(@as(u32, 0), manifest.value.durable_vm_restore_available);
    try std.testing.expectEqual(@as(u32, 1), manifest.value.prefix_vm_reexecution_required);
    try std.testing.expect(!publication.PRODUCTION_ACTIVE);
    try std.testing.expect(!publication.NATIVE_PROOF_ADMISSIBLE);
    try std.testing.expect(!publication.RECURSIVE_ADMISSIBLE);

    var cold = try publication.coldOpenPublication(
        allocator,
        root,
        execution,
        finalBindings(),
    );
    defer cold.deinit();
    try std.testing.expectEqual(@as(usize, 2), cold.value.segments.len);
}

test "V3 segment and manifest codecs reject mutations" {
    const allocator = std.testing.allocator;
    const value = segmentRef(0, 2, 7, 8, 0x51);
    const encoded = try publication.encodeSegmentRefAlloc(allocator, value);
    defer allocator.free(encoded);
    try std.testing.expectEqual(value, try publication.decodeSegmentRef(encoded));
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalSegmentRefContentMismatchV3,
        publication.decodeSegmentRef(encoded),
    );

    var segments = [_]publication.CommittedSegmentV3{
        .{ .segment = segmentRef(0, 2, 7, 8, 0x61), .reference = identity(0x71) },
        .{ .segment = segmentRef(1, 2, 8, 9, 0x62), .reference = identity(0x72) },
    };
    segments[1].segment.prior_authority_id = segments[0].segment.authority_id;
    const manifest_bytes = try publication.encodeManifestAlloc(
        allocator,
        executionAuthority(2),
        finalBindings(),
        7,
        segments[0].segment.prior_authority_id,
        9,
        segments[1].segment.authority_id,
        &segments,
    );
    defer allocator.free(manifest_bytes);
    var manifest = try publication.decodeManifestAlloc(allocator, manifest_bytes);
    defer manifest.deinit();
    try manifest.value.validate();
    manifest_bytes[manifest_bytes.len - 5] ^= 1;
    try std.testing.expectError(
        error.IncrementalCaptureManifestContentMismatchV3,
        publication.decodeManifestAlloc(allocator, manifest_bytes),
    );
}

test "V3 command options distinguish create from full-VM resume" {
    const create = try options.OptionsV3.parse(&.{
        "--retained-materialization-result",
        "/tmp/materialization.json",
        "--publication-root-parent",
        "/tmp",
    });
    try std.testing.expectEqual(options.RootModeV3.create_under_parent, create.root_mode);
    const reopened = try options.OptionsV3.parse(&.{
        "--publication-root",
        "/tmp/existing",
        "--retained-materialization-result",
        "/tmp/materialization.json",
    });
    try std.testing.expectEqual(
        options.RootModeV3.reopen_unsealed,
        reopened.root_mode,
    );
    try std.testing.expectError(error.DuplicateArgument, options.OptionsV3.parse(&.{
        "--publication-root",
        "/tmp/a",
        "--publication-root-parent",
        "/tmp/b",
    }));
}

fn executionAuthority(segment_count: u32) publication.ExecutionAuthorityV3 {
    return .{
        .elf = identity(1),
        .input = identity(2),
        .expected_output = identity(3),
        .execution_profile_semantic_sha256 = [_]u8{4} ** 32,
        .segment_count = segment_count,
        .segment_step_budget = 2,
    };
}

fn finalBindings() publication.FinalBindingsV3 {
    return .{
        .compact_manifest = identity(11),
        .materialization_result = identity(12),
        .source_request = identity(13),
        .journal = identity(14),
        .execution_profile_receipt = identity(15),
    };
}

fn identity(tag: u8) publication.ArtifactIdentityV3 {
    return .{ .byte_count = tag, .sha256 = [_]u8{tag} ** 32 };
}

fn segmentRef(
    index: u32,
    count: u32,
    entry_root: u32,
    exit_root: u32,
    tag: u8,
) publication.SegmentRefV3 {
    return .{
        .segment_index = index,
        .segment_count = count,
        .entry_root = entry_root,
        .exit_root = exit_root,
        .touched_word_count = 1,
        .changed_word_count = 1,
        .frontier_node_count = 1,
        .entry_hash_calls = 1,
        .exit_hash_calls = 1,
        .total_hash_calls = 2,
        .max_shard_log = 4,
        .artifact = identity(tag),
        .compact_tape = identity(tag +% 1),
        .source = identity(tag +% 2),
        .artifact_content_sha256 = [_]u8{tag +% 3} ** 32,
        .transition_v2_content_sha256 = [_]u8{tag +% 4} ** 32,
        .segment_public_wire_id = [_]u32{tag} ** 8,
        .journal_record_sha256 = [_]u8{tag +% 5} ** 32,
        .prior_authority_id = [_]u8{tag +% 6} ** 32,
        .authority_id = [_]u8{tag +% 7} ** 32,
    };
}

fn compactBytes(
    allocator: std.mem.Allocator,
    index: u32,
    source: frontend.recursion.segment_statement_v2.SourceV2,
) ![]u8 {
    const boundary = try minimal.SliceBoundary.init(&.{});
    const ordinary = try allocator.alloc(u32, 0);
    errdefer allocator.free(ordinary);
    const keccak = try allocator.alloc(minimal.ethereum_types.KeccakRecord, 0);
    errdefer allocator.free(keccak);
    const recovery = try allocator.alloc(minimal.ethereum_types.RecoveryRecord, 0);
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
        index,
        source.global_first_cycle,
        1,
        1,
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

fn snapshot(
    side: Side,
    words: []const memory_state.WordState,
) memory_state.Snapshot {
    return .{
        .layout = layout(side),
        .segment_role = .{
            .is_first = side == .left,
            .is_last = side == .right,
        },
        .words = @constCast(words),
    };
}

fn publicAuthority(
    side: Side,
    metadata: frontend.air.public_data_v2.Metadata,
    value: *const public_data.PublicData,
) boundary_v3.SegmentPublicAuthorityV3 {
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

comptime {
    _ = @import("ethereum_incremental_capture_materializer_v3.zig").run;
}
