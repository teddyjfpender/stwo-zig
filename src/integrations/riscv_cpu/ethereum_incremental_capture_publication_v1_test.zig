const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_mod = @import("ethereum_incremental_boundary_artifact_v2.zig");
const authority_mod = @import("ethereum_incremental_boundary_authority_v1.zig");
const capture_mod = @import("ethereum_incremental_boundary_capture_v2.zig");
const publication = @import("ethereum_incremental_capture_publication_v1.zig");
const publication_owner = @import("ethereum_incremental_capture_publication_owner_v1.zig");

const memory_state = frontend.runner.memory_state;

test "incremental publication resumes a committed STWIMT02 prefix without execution" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const bindings = fixtureBindings();
    const session_identity = try bindings.sessionIdentity();
    const entry_root = try artifact_mod.testing.fullRoot(
        allocator,
        &[_]authority_mod.SparseWordV1{},
    );
    const empty_words = [_]memory_state.WordState{};
    const snapshot = snapshotFixture(&empty_words);

    // Simulate a crash after the STWIMT02 file is durable but before its ref.
    var first_capture = try capture_mod.SessionCaptureV2.init(
        allocator,
        session_identity,
        0,
        &snapshot,
        entry_root,
    );
    var authority = try first_capture.apply(
        0,
        &snapshot,
        &.{},
        entry_root,
        entry_root,
    );
    const artifact_bytes = try artifact_mod.encodeAlloc(
        allocator,
        &authority,
        artifact_mod.default_limits,
    );
    defer allocator.free(artifact_bytes);
    authority.deinit();
    first_capture.deinit();
    const artifact_path = try publication.segmentArtifactPathAlloc(
        allocator,
        root,
        0,
    );
    defer allocator.free(artifact_path);
    try artifact_io.publishCreateOnlyDurable(artifact_path, artifact_bytes);

    var resumed_capture = try capture_mod.SessionCaptureV2.init(
        allocator,
        session_identity,
        0,
        &snapshot,
        entry_root,
    );
    defer resumed_capture.deinit();
    var owner = try publication_owner.PublicationOwnerV1.initExisting(
        allocator,
        root,
        &resumed_capture,
        bindings,
    );
    defer owner.deinit();
    try std.testing.expectEqual(@as(u32, 1), try owner.resumeCommittedPrefix());
    try std.testing.expectEqual(@as(u32, 1), resumed_capture.nextSegmentIndex());
    const reference_path = try publication.segmentReferencePathAlloc(
        allocator,
        root,
        0,
    );
    defer allocator.free(reference_path);
    try std.fs.accessAbsolute(reference_path, .{});

    _ = try owner.captureAndPublish(
        1,
        &snapshot,
        &.{},
        entry_root,
        entry_root,
    );
    try std.testing.expectEqual(@as(u32, 2), owner.publishedCount());
    const manifest_path = try publication.manifestPathAlloc(allocator, root);
    defer allocator.free(manifest_path);
    try std.testing.expectError(
        error.FileNotFound,
        std.fs.accessAbsolute(manifest_path, .{}),
    );
    try std.testing.expectError(
        error.IncompleteIncrementalCapturePublication,
        owner.finalize(),
    );
    try std.testing.expect(!publication.PRODUCTION_ACTIVE);
    try std.testing.expect(!publication.NATIVE_PROOF_ADMISSIBLE);
    try std.testing.expect(!publication.RECURSIVE_ADMISSIBLE);
}

test "incremental publication manifest binds all 210 refs and authorities" {
    const allocator = std.testing.allocator;
    const bindings = fixtureBindings();
    var committed: [publication.CANONICAL_SEGMENT_COUNT]publication.CommittedSegmentV1 = undefined;
    const initial_prior = [_]u8{0x80} ** 32;
    var prior = initial_prior;
    for (&committed, 0..) |*destination, index| {
        const tag: u8 = @intCast(index + 1);
        const authority_id = [_]u8{tag} ** 32;
        destination.* = .{
            .segment = .{
                .segment_index = @intCast(index),
                .entry_root = 7,
                .exit_root = 7,
                .changed_word_count = 0,
                .touched_word_count = 0,
                .frontier_node_count = 0,
                .entry_hash_calls = 0,
                .exit_hash_calls = 0,
                .total_hash_calls = 0,
                .max_shard_log = 0,
                .artifact = .{
                    .byte_count = index + 64,
                    .sha256 = [_]u8{tag +% 1} ** 32,
                },
                .artifact_content_sha256 = [_]u8{tag +% 2} ** 32,
                .prior_authority_id = prior,
                .authority_id = authority_id,
            },
            .reference = .{
                .byte_count = 240,
                .sha256 = [_]u8{tag +% 3} ** 32,
            },
        };
        prior = authority_id;
    }
    const encoded = try publication.encodeManifestAlloc(
        allocator,
        bindings,
        7,
        initial_prior,
        7,
        prior,
        &committed,
    );
    defer allocator.free(encoded);
    var decoded = try publication.decodeManifestAlloc(allocator, encoded);
    defer decoded.deinit();
    try decoded.value.validateAgainst(bindings);
    try std.testing.expectEqual(
        publication.CANONICAL_SEGMENT_COUNT,
        decoded.value.segment_count,
    );
    try std.testing.expectEqual(@as(usize, 210), decoded.value.segments.len);

    var wrong_bindings = bindings;
    wrong_bindings.journal.sha256[0] ^= 1;
    try std.testing.expectError(
        error.IncrementalCaptureBindingsMismatch,
        decoded.value.validateAgainst(wrong_bindings),
    );

    const retained_prior = committed[17].segment.prior_authority_id;
    committed[17].segment.prior_authority_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalCaptureChain,
        publication.encodeManifestAlloc(
            allocator,
            bindings,
            7,
            initial_prior,
            7,
            prior,
            &committed,
        ),
    );
    committed[17].segment.prior_authority_id = retained_prior;

    encoded[encoded.len - 33] ^= 1;
    if (publication.decodeManifestAlloc(allocator, encoded)) |mutated| {
        var accepted = mutated;
        accepted.deinit();
        return error.IncrementalManifestMutationAccepted;
    } else |_| {}
}

test "incremental segment ref codec rejects wrong magic and mutations" {
    const allocator = std.testing.allocator;
    const value = publication.SegmentRefV1{
        .segment_index = 4,
        .entry_root = 9,
        .exit_root = 9,
        .changed_word_count = 0,
        .touched_word_count = 0,
        .frontier_node_count = 0,
        .entry_hash_calls = 0,
        .exit_hash_calls = 0,
        .total_hash_calls = 0,
        .max_shard_log = 0,
        .artifact = .{ .byte_count = 128, .sha256 = [_]u8{0x21} ** 32 },
        .artifact_content_sha256 = [_]u8{0x22} ** 32,
        .prior_authority_id = [_]u8{0x23} ** 32,
        .authority_id = [_]u8{0x24} ** 32,
    };
    const encoded = try publication.encodeSegmentRefAlloc(allocator, value);
    defer allocator.free(encoded);
    try std.testing.expectEqual(value, try publication.decodeSegmentRef(encoded));
    encoded[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalCaptureWireHeader,
        publication.decodeSegmentRef(encoded),
    );
}

fn fixtureBindings() publication.SessionBindingsV1 {
    return .{
        .compact_tape = fixtureIdentity(1),
        .source = fixtureIdentity(2),
        .journal = fixtureIdentity(3),
        .elf = fixtureIdentity(4),
        .input = fixtureIdentity(5),
        .output = fixtureIdentity(6),
    };
}

fn fixtureIdentity(tag: u8) publication.ArtifactIdentityV1 {
    return .{ .byte_count = tag, .sha256 = [_]u8{tag} ** 32 };
}

fn snapshotFixture(words: []const memory_state.WordState) memory_state.Snapshot {
    return .{
        .layout = std.mem.zeroes(memory_state.MemoryLayout),
        .segment_role = .{ .is_first = true, .is_last = false },
        .words = @constCast(words),
    };
}
