//! Canonical, declared-window shared-original recursive-root measurement.
//! Producer proofs/captures are destroyed before an independent cold receiver.
const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Producer = @import("../block_v7_window_union_producer_v1.zig");
const Multi = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const Metadata = @import("../block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
const Profile = @import("../../recursion/block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Pipeline = @import("../../recursion/block_v7_union_pipeline_v1.zig");
pub const Result = struct { proof_count: usize, proof_bytes: usize, selection_bytes: usize, artifact_write_ns: u64, metadata_write_ns: u64 };
pub fn finish(artifact: *Producer.Artifact, output: std.fs.Dir) !Result {
    var artifact_live = true;
    defer if (artifact_live) artifact.deinit();
    const a = artifact.allocator;
    const original_limits: Multi.Limits = .{ .max_retained_pcs_bytes = 24 << 30, .max_windows = 8, .receiver = .{ .window_memory = @import("block_v7_real_window_benchmark_resources.zig").memory(.resident) } };
    const options: Pipeline.Limits = .{ .fixed = .{ .max_bytes = 12 << 30 }, .preparation = .{ .max_bytes = 12 << 30 } };
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const metadata_bytes = try Metadata.encode(a, artifact.statement, .{});
    defer a.free(metadata_bytes);
    try output.writeFile(.{ .sub_path = "union-public.json", .data = metadata_bytes });
    const metadata_write_ns = phase.lap();
    // Preserve the completed source STARK before recursion. A later compiler,
    // witness or resource failure must not force its wide witness to be proved
    // again just to diagnose the recursive stage.
    const source_artifact = blk: {
        const Codec = @import("../block_v7_multi_union_codec_v1.zig").ForMode(true);
        const bytes = try Codec.encode(a, artifact.proof.view(), artifact.statement.input, .{ .scope = original_limits, .verification_bytes = 24 << 30 });
        defer a.free(bytes);
        try output.writeFile(.{ .sub_path = "union.proof", .data = bytes });
        break :blk .{ .bytes = bytes.len, .sha256 = Capture.sha(bytes) };
    };
    const source_archive_ns = phase.lap();
    const metadata = try Metadata.decode(a, metadata_bytes, artifact.statement.trusted, .{});
    defer metadata.deinit();
    const metadata_decode_ns = phase.lap();
    const view = artifact.proof.view();
    var capture = try Multi.verifyViewAndCapture(a, metadata.trusted, metadata.input, &view, original_limits);
    var capture_live = true;
    defer if (capture_live) capture.deinit();
    const original_verification_ns = phase.lap();
    const original_stats = artifact.stats;
    artifact.deinit();
    artifact_live = false;
    const profile = try Profile.Owned.derive(a, metadata, &capture.claims, .{ .original = original_limits });
    var profile_live = true;
    defer if (profile_live) profile.deinit();
    const profile_ns = phase.lap();
    var root = try Pipeline.produce(a, profile, &capture, options);
    defer root.deinit();
    const recursive_production_ns = phase.lap();
    profile.deinit();
    profile_live = false;
    capture.deinit();
    capture_live = false;
    const release_ns = phase.lap();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    try output.writeFile(.{ .sub_path = "union.claims", .data = root.claims });
    const artifact_write_ns = phase.lap();
    var verified = try Pipeline.verify(a, root.bytes, root.claims, metadata, original_limits, options);
    defer verified.deinit();
    if (verified.summary.scope != .declared_window) return error.InvalidWindowProofScope;
    const fresh_verification_ns = phase.lap();
    const detail = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-window-shared-recursive-root-verification-v1",
        .scope = "declared_nonterminal_window_to_shared_recursive_root",
        .original_proofs_destroyed = true,
        .producer_capture_destroyed = true,
        .producer_parent_rows_destroyed = true,
        .independent_fixed_key_reconstructed = true,
        .canonical_security = true,
        .query_count = 70,
        .pow_bits = 26,
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .source_stark_count = 1,
        .recursive_stark_count = 1,
        .metadata_write_ns = metadata_write_ns,
        .source_archive_ns = source_archive_ns,
        .source_proof_bytes = source_artifact.bytes,
        .source_proof_sha256 = std.fmt.bytesToHex(source_artifact.sha256, .lower),
        .metadata_decode_ns = metadata_decode_ns,
        .original_verification_ns = original_verification_ns,
        .profile_ns = profile_ns,
        .recursive_production_ns = recursive_production_ns,
        .recursive = root.stats,
        .producer_release_ns = release_ns,
        .artifact_write_ns = artifact_write_ns,
        .fresh_verification_ns = fresh_verification_ns,
        .whole_ns = whole.read(),
        .root_bytes = root.bytes.len,
        .root_sha256 = std.fmt.bytesToHex(Capture.sha(root.bytes), .lower),
        .claims_bytes = root.claims.len,
        .claims_sha256 = std.fmt.bytesToHex(Capture.sha(root.claims), .lower),
        .metadata_bytes = metadata_bytes.len,
        .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(metadata_bytes), .lower),
        .verified = verified.summary,
        .original_producer = original_stats,
    }, .{ .whitespace = .indent_2 });
    defer a.free(detail);
    try output.writeFile(.{ .sub_path = "union-root-verification.json", .data = detail });
    return .{ .proof_count = 1, .proof_bytes = root.bytes.len, .selection_bytes = 0, .artifact_write_ns = artifact_write_ns, .metadata_write_ns = metadata_write_ns };
}
