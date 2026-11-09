//! Exact, non-promotional gates for the recursion FRI cost frontier.

const std = @import("std");
const frontier_mod = @import("../fri_profile_frontier.zig");
const protocol = @import("stwo_riscv_recursion_air").protocol_recursion_protocol;

const V1_COMPARISON_DIGEST_HEX =
    "1c4ef8a500738a109a6612868119b86f7416f08116ebf5abd8a6f36a539efde0";

test "R-012 FRI frontier preserves the V1 configured ledger while exposing tradeoffs" {
    const frontier = try frontier_mod.v1Comparison(24);
    try frontier.validate();
    try std.testing.expectEqual(@as(u8, 6), frontier.count);
    try std.testing.expectEqual(
        @as(u32, protocol.PCS_CONFIG.securityBits()),
        frontier.configured_security_floor,
    );

    const expected_queries = [_]u32{ 193, 97, 65, 49, 39, 33 };
    const expected_authentication = [_]u64{ 12_738, 6_984, 5_070, 4_116, 3_510, 3_168 };
    const expected_folds = [_]u64{ 18_528, 9_312, 6_240, 4_704, 3_744, 3_168 };
    for (
        frontier.active(),
        expected_queries,
        expected_authentication,
        expected_folds,
        1..,
    ) |candidate, queries, authentication, folds, blowup| {
        try std.testing.expectEqual(@as(u32, @intCast(blowup)), candidate.log_blowup_factor);
        try std.testing.expectEqual(queries, candidate.n_queries);
        try std.testing.expect(candidate.configured_security_bits >= frontier.configured_security_floor);
        try std.testing.expectEqual(@as(u32, 1) << @intCast(blowup), candidate.domain_expansion);
        try std.testing.expectEqual(@as(u64, queries) * 4, candidate.raw_trace_query_paths);
        try std.testing.expectEqual(authentication, candidate.fri_authentication_digests_upper_bound);
        try std.testing.expectEqual(folds, candidate.fri_fold_values_upper_bound);
        try std.testing.expectEqual(@as(u64, 1) << @intCast(blowup), candidate.terminal_domain_values);
    }
    try std.testing.expectEqualStrings(
        V1_COMPARISON_DIGEST_HEX,
        &std.fmt.bytesToHex(try frontier.identityDigest(), .lower),
    );
}

test "R-012 FRI frontier is allocation free failure closed and nondominated" {
    const frontier = try frontier_mod.build(24, 1, 6, 16, 209);
    for (frontier.active(), 0..) |candidate, index| {
        for (frontier.active(), 0..) |other, other_index| {
            if (index != other_index)
                try std.testing.expect(!other.dominates(candidate));
        }
    }

    try std.testing.expectError(
        error.InvalidFrontier,
        frontier_mod.build(24, 0, 6, 16, 209),
    );
    try std.testing.expectError(
        error.InvalidConfiguredSecurity,
        frontier_mod.build(24, 1, 1, 16, 16),
    );

    var corrupted = frontier;
    corrupted.candidates[0].n_queries -= 1;
    try std.testing.expectError(error.InvalidFrontier, corrupted.validate());
}
