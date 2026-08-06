const std = @import("std");
const reviewed = @import("typed_air_h009_artifacts");
const artifact = @import("typed_poseidon2_frontier_artifact.zig");
const manifest = @import("materialization_frontier_manifest.zig");

test "H-009 reviewed frontier decodes and both views regenerate byte exactly" {
    var decoded = try manifest.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();

    var tsv: std.ArrayList(u8) = .empty;
    defer tsv.deinit(std.testing.allocator);
    try artifact.writeTsv(tsv.writer(std.testing.allocator), decoded.view());
    try std.testing.expectEqualStrings(reviewed.h009_poseidon2_frontier_tsv, tsv.items);

    var markdown: std.ArrayList(u8) = .empty;
    defer markdown.deinit(std.testing.allocator);
    try artifact.writeMarkdown(markdown.writer(std.testing.allocator), decoded.view());
    try std.testing.expectEqualStrings(
        reviewed.h009_poseidon2_frontier_markdown,
        markdown.items,
    );
}

test "H-009 reviewed frontier pins identity accounting and the exact plateau" {
    var decoded = try manifest.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();

    try expectDigest(
        decoded.identity.semantic_digest,
        "9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed",
    );
    try expectDigest(
        decoded.cost_model.fixed_program_digest,
        "ef32024ba1d25b470c217ef96af95b52038948c67f6ac4ce1e14875bf68ea6a5",
    );
    try expectDigest(
        decoded.cost_model.cost_model_digest,
        "12670408a3c3020c62d279c997338d9c427d0755697aca2a954f6a1d88a9ba11",
    );
    try expectDigest(
        decoded.search.configuration_digest,
        "32dc4c0b5e265c74b159a6e661d4f6f0b06f3b54d62efe286364b5dae92db8ed",
    );
    try expectDigest(
        decoded.run.result_digest,
        "7948117553242d3154a8bd09ca1664c4bf6e5cbcc515a4ce80461cf544d39193",
    );
    try expectDigest(
        decoded.baseline.cut_digest,
        "b10cb7f66e3519788ecec6edc4095541a24eaf642a3ed8877fbe87c85e8ba9c5",
    );
    try expectDigest(
        decoded.baseline.proposal_digest,
        "7a585031ef8710d62adac55d1c2d8072c0b2a6ce82a562b4862d4329623a23ef",
    );

    try std.testing.expectEqual(@as(u32, 1_124), decoded.run.attempted_evaluations);
    try std.testing.expectEqual(@as(u32, 430), decoded.run.feasible_unique_proposals);
    try std.testing.expectEqual(@as(u32, 694), decoded.run.rejected_infeasible);
    try std.testing.expectEqual(@as(u32, 0), decoded.run.duplicate_proposals);
    try std.testing.expectEqual(@as(u16, 1), decoded.run.passes_completed);
    try std.testing.expect(!decoded.run.budget_exhausted);
    try std.testing.expect(!decoded.run.frontier_truncated);
    try std.testing.expectEqual(@as(usize, 126), decoded.frontier.len);
    try std.testing.expectEqualDeep(manifest.CostVector{
        .materialization_count = 426,
        .base_main_columns = 19,
        .candidate_main_columns = 445,
        .direct_roots = 430,
        .interaction_columns = 8,
        .canonical_direct_nodes = 3_460,
        .canonical_direct_additions = 1_346,
        .canonical_direct_subtractions = 429,
        .canonical_direct_negations = 0,
        .canonical_direct_multiplications = 1_080,
        .unique_committed_column_reads = 445,
        .canonical_streaming_peak_live_nodes = 39,
        .semantic_witness_nodes = 2_171,
    }, decoded.baseline.cost);
    for (decoded.frontier) |proposal| {
        try std.testing.expectEqualDeep(decoded.baseline.cost, proposal.cost);
        try expectScenarioCosts(decoded.baseline.scenario_costs, proposal.scenario_costs);
    }
    try expectDigest(
        decoded.frontier[0].proposal_digest,
        "009f28b183b765331f19cb21f939aa2c08c58fe0ab5b133476d713e897919ab1",
    );
    try expectDigest(
        decoded.frontier[decoded.frontier.len - 1].proposal_digest,
        "feb957cf4784a7c2a062b4e16e58ee1708fe06b11062d0eee2a8aaa0ec05970e",
    );

    var raw_sha: manifest.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(reviewed.h009_poseidon2_frontier, &raw_sha, .{});
    try expectDigest(
        raw_sha,
        "5ead00cfcb8cfd396836be9cc3a79ed80bfb0b8bc7913a1c6ab38dbcff879494",
    );
}

fn expectDigest(actual: manifest.Digest, expected_hex: *const [64]u8) !void {
    var expected: manifest.Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

fn expectScenarioCosts(
    expected: []const manifest.ScenarioCost,
    actual: []const manifest.ScenarioCost,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |lhs, rhs| try std.testing.expectEqualDeep(lhs, rhs);
}
