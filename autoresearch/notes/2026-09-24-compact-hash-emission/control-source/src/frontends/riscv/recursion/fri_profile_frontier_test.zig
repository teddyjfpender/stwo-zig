//! Exact, non-promotional gates for the recursion FRI cost frontier.

const std = @import("std");
const circuit_mod = @import("air/fri_verifier_circuit.zig");
const input_witness = @import("air/fri_verifier_input_witness.zig");
const lowering = @import("air/fri_verifier_lowering.zig");
const fixed_profile = @import("fixed_profile.zig");
const frontier_mod = @import("fri_profile_frontier.zig");
const protocol = @import("protocol.zig");

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

test "R-012 FRI frontier exact recursive arithmetic measurement" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(
        allocator,
        "STWO_RECURSION_FRI_CIRCUIT_FRONTIER",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(enabled);

    const column_log_degree: u32 = 20;
    const frontier = try frontier_mod.v1Comparison(column_log_degree);
    for (frontier.active()) |candidate| {
        var config = protocol.PCS_CONFIG.fri_config;
        config.log_blowup_factor = candidate.log_blowup_factor;
        config.n_queries = candidate.n_queries;
        const schedule = try fixed_profile.FriSchedule.init(
            column_log_degree,
            config,
        );
        var fold_widths: [circuit_mod.MAX_FRI_LAYERS]u32 = undefined;
        for (schedule.active(), fold_widths[0..schedule.count]) |
            round,
            *width,
        | width.* = round.fold_width;
        const profile = circuit_mod.Profile{
            .lifting_log_size = try std.math.add(
                u32,
                column_log_degree,
                candidate.log_blowup_factor,
            ),
            .log_blowup_factor = candidate.log_blowup_factor,
            .log_last_layer_degree_bound = config.log_last_layer_degree_bound,
            .fold_widths = fold_widths[0..schedule.count],
            .query_count = candidate.n_queries,
        };

        var circuits: [3]circuit_mod.Circuit = undefined;
        var circuit_count: usize = 0;
        defer for (circuits[0..circuit_count]) |*circuit| circuit.deinit();
        while (circuit_count < circuits.len) : (circuit_count += 1)
            circuits[circuit_count] = try circuit_mod.build(allocator, profile);
        const reference = try input_witness.Reference.seal(.{
            .{ .verifier_id = 0, .circuit_id = 301, .circuit = &circuits[0] },
            .{ .verifier_id = 1, .circuit_id = 302, .circuit = &circuits[1] },
            .{ .verifier_id = 2, .circuit_id = 303, .circuit = &circuits[2] },
        });
        var plan = try lowering.Plan.init(allocator, reference);
        defer plan.deinit();
        const counts = plan.counts(.segment_leaf);
        std.debug.print(
            "\n  A1_CIRCUIT blowup_log={d} queries={d} nodes={d} " ++
                "inputs={d} outputs={d} mul={d} inv={d} linear={d} " ++
                "public={d}\n",
            .{
                candidate.log_blowup_factor,
                candidate.n_queries,
                circuits[0].nodes.len,
                circuits[0].bindings.len,
                circuits[0].outputs.len,
                counts.multiply,
                counts.inverse,
                counts.linear,
                counts.public,
            },
        );
    }
}
