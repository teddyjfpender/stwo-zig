const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const m31 = @import("stwo_core").fields.m31;

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const capture = @import("ethereum_incremental_capture_publication_v4.zig");
const owner_mod =
    @import("ethereum_incremental_public_wire_publication_owner_v4.zig");
const publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const reconstruction =
    @import("ethereum_incremental_role_public_reconstruction_v4.zig");
const support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

test "V4 public-wire companion cold-adopts a crash prefix and seals last" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const fixture = try support.Fixture.init();
    var left = try support.OwnedWire.init(allocator, &fixture.leftSource());
    defer left.deinit();
    var right = try support.OwnedWire.init(allocator, &fixture.rightSource());
    defer right.deinit();
    const execution = executionAuthority();

    const v4_left = try publishV4Ref(
        allocator,
        root,
        segmentRef(0, left.data.wireId(), identity(31), digest(41), digest(42)),
    );
    var first = try owner_mod.PublicationOwnerV4.initExisting(
        allocator,
        root,
        execution,
    );
    _ = try first.captureAndPublish(&left.data, v4_left);
    first.deinit();

    // A new process recomputes the same wire and adopts the exact durable
    // STWIPW04/STWIPR04 pair instead of replacing either file.
    var resumed = try owner_mod.PublicationOwnerV4.initExisting(
        allocator,
        root,
        execution,
    );
    defer resumed.deinit();
    _ = try resumed.captureAndPublish(&left.data, v4_left);
    var right_ref = segmentRef(
        1,
        right.data.wireId(),
        identity(32),
        v4_left.segment.authority_id,
        digest(43),
    );
    right_ref.entry_root = v4_left.segment.exit_root;
    const v4_right = try publishV4Ref(allocator, root, right_ref);
    _ = try resumed.captureAndPublish(&right.data, v4_right);

    const v4_segments = [_]capture.CommittedSegmentV4{ v4_left, v4_right };
    const v4_manifest = try publishV4Manifest(
        allocator,
        root,
        execution,
        &v4_segments,
    );
    var manifest = try resumed.finalize(
        finalBindings(),
        v4_manifest,
    );
    defer manifest.deinit();
    try std.testing.expectEqual(@as(u32, 2), manifest.value.segment_count);
    try std.testing.expectEqual(v4_manifest, manifest.value.v4_manifest);
    try std.testing.expect(!publication.PRODUCTION_ACTIVE);
    try std.testing.expect(!publication.PROOF_ADMISSIBLE);

    var cold = try publication.coldOpenPublication(
        allocator,
        root,
        execution,
        finalBindings(),
        v4_manifest,
    );
    defer cold.deinit();
    try std.testing.expectEqual(@as(usize, 2), cold.value.segments.len);

    var wrong = v4_left;
    wrong.segment.source = identity(99);
    try std.testing.expectError(
        error.IncrementalPublicWireV4SegmentReferenceMismatch,
        publication.coldOpenSegment(allocator, root, 0, wrong),
    );
}

test "V4 public-wire codecs reject field ref and manifest mutations" {
    const allocator = std.testing.allocator;
    const fixture = try support.Fixture.init();
    var wire = try support.OwnedWire.init(allocator, &fixture.leftSource());
    defer wire.deinit();
    const coordinate = publication.CoordinateV4{
        .segment_index = 0,
        .segment_count = 2,
    };
    const encoded = try publication.encodeWireAlloc(
        allocator,
        coordinate,
        &wire.data,
    );
    defer allocator.free(encoded);
    var decoded = try publication.decodeWireAlloc(allocator, encoded);
    decoded.deinit();

    const noncanonical = try allocator.dupe(u8, encoded);
    defer allocator.free(noncanonical);
    std.mem.writeInt(u32, noncanonical[64..68], m31.Modulus, .little);
    try std.testing.expectError(
        error.NonCanonicalIncrementalPublicWireM31,
        publication.decodeWireAlloc(allocator, noncanonical),
    );
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalPublicWireContentMismatchV4,
        publication.decodeWireAlloc(allocator, encoded),
    );

    const ref_value = publicRef(0, wire.data.wireId(), 51);
    const ref_bytes = try publication.encodeSegmentRefAlloc(allocator, ref_value);
    defer allocator.free(ref_bytes);
    try std.testing.expectEqual(ref_value, try publication.decodeSegmentRef(ref_bytes));
    ref_bytes[ref_bytes.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalPublicWireRefContentMismatchV4,
        publication.decodeSegmentRef(ref_bytes),
    );

    const segments = [_]publication.CommittedSegmentV4{
        .{ .segment = publicRef(0, wire.data.wireId(), 61), .reference = identity(71) },
        .{ .segment = publicRef(1, wire.data.wireId(), 62), .reference = identity(72) },
    };
    const manifest_bytes = try publication.encodeManifestAlloc(
        allocator,
        executionAuthority(),
        finalBindings(),
        identity(73),
        &segments,
    );
    defer allocator.free(manifest_bytes);
    var manifest = try publication.decodeManifestAlloc(allocator, manifest_bytes);
    manifest.deinit();
    manifest_bytes[manifest_bytes.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalPublicWireManifestContentMismatchV4,
        publication.decodeManifestAlloc(allocator, manifest_bytes),
    );
}

test "V4 role-aware public data is reconstructed from wire layout and raw IO" {
    const allocator = std.testing.allocator;
    const fixture = try support.Fixture.init();
    var left = try support.OwnedWire.init(allocator, &fixture.leftSource());
    defer left.deinit();
    const input = [_]u8{ 11, 0, 0, 0 };
    const left_sources = [_]@import("ethereum_incremental_boundary_authority_v4.zig").WordBoundarySourceV4{.{
        .word = .{
            .addr = 0x2000,
            .initial_word = 11,
            .final_word = 11,
            .final_clock = 0,
            .role = .{ .is_public_input = true },
        },
        .entry_clock = 0,
    }};
    var left_public = try reconstruction.reconstruct(
        allocator,
        &left.data,
        layout(),
        &input,
        "ignored-until-final",
        &left_sources,
    );
    defer left_public.deinit();
    try std.testing.expectEqual(@as(u32, 4), left_public.value.io_entries.input_len);
    try std.testing.expectEqual(@as(u32, 11), left_public.input_words[0]);
    try std.testing.expectEqual(@as(usize, 0), left_public.output_words.len);

    var words = fixture.right_words;
    words[0].final_word = 1;
    words[1].final_word = 0x41;
    var right_source = fixture.rightSource();
    right_source.memory_words = &words;
    var local_exit_register_clocks = right_source.exit_register_clocks;
    local_exit_register_clocks[1] = 2;
    right_source.exit_register_clocks = local_exit_register_clocks;
    var right = try support.OwnedWire.init(allocator, &right_source);
    defer right.deinit();
    const right_sources = [_]@import("ethereum_incremental_boundary_authority_v4.zig").WordBoundarySourceV4{
        .{
            .word = .{
                .addr = 0x2000,
                .initial_word = 12,
                .final_word = 1,
                .final_clock = 1,
                .role = .{ .is_public_output = true },
            },
            .entry_clock = 0,
        },
        .{
            .word = .{
                .addr = 0x2004,
                .initial_word = 0,
                .final_word = 0x41,
                .final_clock = 2,
                .role = .{ .is_public_output = true },
            },
            .entry_clock = 0,
        },
    };
    var right_public = try reconstruction.reconstruct(
        allocator,
        &right.data,
        layout(),
        &input,
        "A",
        &right_sources,
    );
    defer right_public.deinit();
    try std.testing.expectEqual(@as(usize, 2), right_public.output_words.len);
    try std.testing.expectEqual(@as(u32, 1), right_public.output_words[0].value);
    try std.testing.expectEqual(@as(u32, 0x41), right_public.output_words[1].value);
    try std.testing.expectEqual(@as(u32, 1), right_public.output_words[0].clock);
    try std.testing.expectEqual(@as(u32, 2), right_public.output_words[1].clock);
    try std.testing.expectError(
        error.IncrementalRolePublicOutputMismatchV4,
        reconstruction.reconstruct(
            allocator,
            &right.data,
            layout(),
            &input,
            "B",
            &right_sources,
        ),
    );
}

fn publishV4Ref(
    allocator: std.mem.Allocator,
    root: []const u8,
    value: capture.SegmentRefV4,
) !capture.CommittedSegmentV4 {
    const bytes = try capture.encodeSegmentRefAlloc(allocator, value);
    defer allocator.free(bytes);
    const path = try capture.segmentReferencePathAlloc(
        allocator,
        root,
        value.segment_index,
    );
    defer allocator.free(path);
    try artifact_io.publishCreateOnlyDurable(path, bytes);
    return .{
        .segment = value,
        .reference = capture.ArtifactIdentityV4.fromBytes(bytes),
    };
}

fn publishV4Manifest(
    allocator: std.mem.Allocator,
    root: []const u8,
    execution: capture.ExecutionAuthorityV4,
    segments: []const capture.CommittedSegmentV4,
) !capture.ArtifactIdentityV4 {
    const bytes = try capture.encodeManifestAlloc(
        allocator,
        execution,
        finalBindings(),
        segments[0].segment.entry_root,
        segments[0].segment.prior_authority_id,
        segments[segments.len - 1].segment.exit_root,
        segments[segments.len - 1].segment.authority_id,
        segments,
    );
    defer allocator.free(bytes);
    const path = try capture.manifestPathAlloc(allocator, root);
    defer allocator.free(path);
    try artifact_io.publishCreateOnlyDurable(path, bytes);
    return capture.ArtifactIdentityV4.fromBytes(bytes);
}

fn executionAuthority() capture.ExecutionAuthorityV4 {
    return .{
        .elf = identity(1),
        .input = identity(2),
        .expected_output = identity(3),
        .execution_profile_semantic_sha256 = digest(4),
        .segment_count = 2,
        .segment_step_budget = 1 << 20,
    };
}

fn finalBindings() capture.FinalBindingsV4 {
    return .{
        .compact_manifest = identity(11),
        .materialization_result = identity(12),
        .source_request = identity(13),
        .journal = identity(14),
        .execution_profile_receipt = identity(15),
    };
}

fn segmentRef(
    index: u32,
    wire_id: frontend.air.public_data_v2.Digest,
    source: capture.ArtifactIdentityV4,
    prior: [32]u8,
    authority: [32]u8,
) capture.SegmentRefV4 {
    return .{
        .segment_index = index,
        .segment_count = 2,
        .entry_root = 100 + index,
        .exit_root = 101 + index,
        .touched_word_count = 1,
        .changed_word_count = 1,
        .frontier_node_count = 1,
        .entry_hash_calls = 1,
        .exit_hash_calls = 1,
        .total_hash_calls = 2,
        .max_shard_log = 1,
        .artifact = identity(@intCast(21 + index)),
        .compact_tape = identity(@intCast(23 + index)),
        .source = source,
        .artifact_content_sha256 = digest(@intCast(25 + index)),
        .transition_v2_content_sha256 = digest(@intCast(27 + index)),
        .segment_public_wire_id = wire_id,
        .journal_record_sha256 = digest(@intCast(29 + index)),
        .prior_authority_id = prior,
        .authority_id = authority,
    };
}

fn publicRef(
    index: u32,
    wire_id: frontend.air.public_data_v2.Digest,
    tag: u8,
) publication.SegmentRefV4 {
    return .{
        .coordinate = .{ .segment_index = index, .segment_count = 2 },
        .wire_id = wire_id,
        .wire_artifact = identity(tag),
        .v4_segment_reference = identity(tag +% 1),
        .source = identity(tag +% 2),
        .journal_record_sha256 = digest(tag +% 3),
    };
}

fn identity(tag: u8) capture.ArtifactIdentityV4 {
    return .{ .byte_count = tag, .sha256 = digest(tag) };
}

fn digest(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
}

fn layout() frontend.runner.memory_state.MemoryLayout {
    return .{
        .program_base = 0,
        .program_end = 0x1000,
        .data_base = 0x1000,
        .data_end = 0x3000,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x2000,
        .io_end = 0x3000,
        .input_base = 0x2000,
        .input_end = 0x2008,
        .output_len_addr = 0x2000,
        .output_data_addr = 0x2004,
        .output_base = 0x2000,
        .output_end = 0x3000,
    };
}
