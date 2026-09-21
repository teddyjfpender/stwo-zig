//! CLI admission stays explicit across materialization, capture and full-leaf proof.
const std = @import("std");
const geometry = @import("ethereum_incremental_campaign_geometry_v1.zig");
const capture = @import("ethereum_incremental_capture_materializer_options_v4.zig");
const fast = @import("ethereum_incremental_capture_postprocess_command_v4.zig");
const replay = @import("ethereum_incremental_full_leaf_replay_command_v4.zig");
const materialize = @import("ethereum_block_leaf_materializer_options.zig");

comptime {
    _ = geometry;
}

test "retained campaign CLI preserves legacy and explicitly selects authenticated geometry" {
    const legacy = try capture.OptionsV4.parse(&.{
        "--retained-materialization-result", "materialization.json", "--publication-root", "root",
    });
    try std.testing.expectEqual(geometry.SelectionV1.legacy_210, legacy.campaign_geometry);
    const selected = try capture.OptionsV4.parse(&.{
        "--retained-materialization-result", "materialization.json", "--publication-root", "root",
        "--campaign-geometry",               "authenticated-v1",
    });
    try std.testing.expectEqual(geometry.SelectionV1.authenticated_v1, selected.campaign_geometry);
    const selected_fast = try fast.OptionsV4.parse(&.{
        "--retained-materialization-result", "materialization.json", "--publication-root",  "root",
        "--cold-workers",                    "1",                    "--campaign-geometry", "authenticated-v1",
    });
    try std.testing.expectEqual(geometry.SelectionV1.authenticated_v1, selected_fast.campaign_geometry);
    try std.testing.expectEqual(@as(usize, 1), selected_fast.cold_workers);
    try std.testing.expectError(error.UnsupportedIncrementalCampaignGeometryV1, capture.OptionsV4.parse(&.{
        "--retained-materialization-result", "materialization.json", "--publication-root", "root",
        "--campaign-geometry",               "authenticated-v2",
    }));
}

test "prepared CPU leaf requires explicit policy and preserves retained campaign arguments" {
    const args = [_][]const u8{
        "--retained-materialization-result", "materialization.json", "--publication-root", "root",
        "--segment-index",                   "1",                    "--output",           "leaf.stwief04",
        "--campaign-geometry",               "authenticated-v1",     "--workers",          "1",
        "--host-byte-budget",                "8589934592",           "--host-byte-limit",  "17179869184",
    };
    const selected = try replay.PreparedCpuOptionsV1.parse(&args);
    try std.testing.expectEqual(@as(usize, 1), selected.worker_count);
    try std.testing.expectEqual(@as(usize, 8589934592), selected.host_byte_budget);
    const forwarded = try replay.Options.parse(selected.replay_arguments[0..selected.replay_argument_count]);
    try std.testing.expectEqual(geometry.SelectionV1.authenticated_v1, forwarded.campaign_geometry);
    try std.testing.expectEqual(@as(u32, 1), forwarded.segment_index);
    try std.testing.expectError(error.MissingArgument, replay.PreparedCpuOptionsV1.parse(args[0..14]));
    var duplicate = args;
    duplicate[14] = "--workers";
    try std.testing.expectError(error.DuplicateArgument, replay.PreparedCpuOptionsV1.parse(&duplicate));
}

test "materializer snapshot policy permits synchronous laptop capture without changing default" {
    const args = [_][]const u8{
        "--elf",           "guest.elf",        "--input",               "input.bin",                                           "--expected-output", "output.bin",
        "--journal",       "execution.ndjson", "--proof-profile",       "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1", "--result",          "materialization.json",
        "--segment-count", "121",              "--segment-step-budget", "2097152",                                             "--source-request",  "source.json",
        "--source-root",   "sources",          "--snapshot-workers",    "1",
    };
    const selected = try materialize.Options.parse(&args);
    try std.testing.expectEqual(@as(usize, 1), selected.snapshot_workers);
    try std.testing.expectEqual(@as(u32, 121), selected.segment_count);
    const legacy = try materialize.Options.parse(args[0..20]);
    try std.testing.expectEqual(@as(usize, 16), legacy.snapshot_workers);
    var invalid = args;
    invalid[21] = "0";
    try std.testing.expectError(error.InvalidSnapshotBatchGeometry, materialize.Options.parse(&invalid));
}

test "retained replay claim admission is explicit across CPU prepared forwarding" {
    const profile = @import("ethereum_incremental_full_leaf_profile_v4.zig");
    const base = [_][]const u8{
        "--retained-materialization-result", "materialization.json", "--publication-root", "root",
        "--segment-index",                   "1",                    "--output",           "leaf.stwief04",
    };
    try std.testing.expectEqual(profile.ClaimAdmissionV4.legacy_aggregate_v2, (try replay.Options.parse(&base)).claim_admission);
    inline for (std.meta.tags(profile.ClaimAdmissionV4)) |admission| {
        const args = base ++ [_][]const u8{
            "--claim-admission",          @tagName(admission),  "--campaign-geometry",            "authenticated-v1",
            "--global-metadata-output",   "leaf.metadata.json", "--selected-leaf-admission-root", "selected-leaf",
            "--pcs-retained-byte-budget", "25769803776",        "--workers",                      "1",
            "--host-byte-budget",         "17179869184",        "--host-byte-limit",              "34359738368",
        };
        const selected = try replay.PreparedCpuOptionsV1.parse(&args);
        const forwarded = try replay.Options.parse(selected.replay_arguments[0..selected.replay_argument_count]);
        try std.testing.expectEqual(admission, forwarded.claim_admission);
        try std.testing.expectEqualStrings("leaf.metadata.json", forwarded.global_metadata_output.?);
        try std.testing.expectEqualStrings("selected-leaf", forwarded.selected_leaf_admission_root.?);
        try std.testing.expectEqual(@as(usize, 25769803776), forwarded.pcs_retained_byte_budget.?);
        try std.testing.expectEqual(geometry.SelectionV1.authenticated_v1, forwarded.campaign_geometry);
    }
    const invalid = base ++ [_][]const u8{ "--claim-admission", "5" };
    try std.testing.expectError(error.UnsupportedIncrementalClaimAdmissionV4, replay.Options.parse(&invalid));
    const duplicate = base ++ [_][]const u8{ "--claim-admission", "legacy_aggregate_v2", "--claim-admission", "field_authority_v4" };
    try std.testing.expectError(error.DuplicateArgument, replay.Options.parse(&duplicate));
}

comptime {
    _ = @import("ethereum_incremental_full_leaf_residency_preflight_v1.zig");
}

comptime {
    _ = @import("ethereum_block_leaf_compact_manifest.zig");
}

test "explicit one worker proof pool binds commitment helpers without changing default" {
    const work_pool = @import("stwo_prover_engine").work_pool;
    const ProofExecutionPool = @import("stwo_riscv_frontend").testing.prover_orchestration.ProofExecutionPool;
    const before = work_pool.testing.activeScopedPoolCount();
    var legacy: ProofExecutionPool = .{};
    try legacy.initInPlace(std.testing.allocator, null);
    defer legacy.deinit();
    try std.testing.expect(legacy.get() == null);
    try std.testing.expectEqual(before, work_pool.testing.activeScopedPoolCount());
    var serial: ProofExecutionPool = .{};
    try serial.initInPlace(std.testing.allocator, .{ .worker_count = 1, .host_byte_budget = 1024 * 1024 });
    defer serial.deinit();
    try std.testing.expect(serial.get() != null);
    try std.testing.expectEqual(serial.get(), work_pool.getGlobalPool());
    try std.testing.expectEqual(before + 1, work_pool.testing.activeScopedPoolCount());
}
