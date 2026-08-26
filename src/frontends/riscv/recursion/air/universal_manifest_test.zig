//! Whole-roster closure gates for the exact universal recursion manifest.

const std = @import("std");
const manifest_mod = @import("universal_manifest.zig");
const query_bits = @import("query_bits.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const roster = @import("universal_roster.zig");

// Recomputed from the complete ordered geometry below. In particular, row 20
// now binds the profile-owned raw-query-to-position projection parameters.
const FIXTURE_SEAL_HEX =
    "4291b670ee1b6ce9b7b0f6d8fd60a241a9a38b81f49a4617bf6f2e86771efade";

test "R-012 universal manifest closes all 36 rows in exact protocol order" {
    const log_sizes = fixtureLogSizes();
    const manifest = try manifest_mod.build(log_sizes);
    try manifest.validate();
    try std.testing.expectEqual(@as(u8, roster.COMPONENT_COUNT), manifest.roster_count);

    var prior_preprocessed: u32 = 0;
    var prior_main: u32 = 0;
    var prior_interaction: u32 = 0;
    var prior_constraints: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count], 0..) |row, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), row);
        const placement = manifest.placements[row].?;
        try std.testing.expectEqual(prior_preprocessed, placement.preprocessed_offset);
        try std.testing.expectEqual(prior_main, placement.main_offset);
        try std.testing.expectEqual(prior_interaction, placement.interaction_offset);
        try std.testing.expectEqual(prior_constraints, placement.constraint_offset);
        try std.testing.expectEqual(row, placement.claimed_sum_index);
        try std.testing.expect(!std.mem.allEqual(
            u8,
            &placement.geometry.semantic_digest,
            0,
        ));
        prior_preprocessed += placement.geometry.preprocessed_columns;
        prior_main += placement.geometry.main_columns;
        prior_interaction += placement.geometry.interaction_columns;
        prior_constraints += placement.geometry.direct_constraints +
            placement.geometry.interaction_batches;
    }
    try std.testing.expectEqual(prior_preprocessed, manifest.total_preprocessed_columns);
    try std.testing.expectEqual(prior_main, manifest.total_main_columns);
    try std.testing.expectEqual(prior_interaction, manifest.total_interaction_columns);
    try std.testing.expectEqual(prior_constraints, manifest.total_constraints);
    try std.testing.expectEqual(@as(u32, 570), manifest.total_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 1044), manifest.total_main_columns);
    try std.testing.expectEqual(@as(u32, 560), manifest.total_interaction_columns);
    try std.testing.expectEqual(@as(u32, 1312), manifest.total_constraints);
    const query_placement = manifest.placements[
        @intFromEnum(roster.Component.query_bits)
    ].?;
    try std.testing.expectEqualSlices(
        u8,
        &query_bits.SEMANTIC_DIGEST,
        &query_placement.geometry.semantic_digest,
    );
    try std.testing.expectEqualStrings(
        FIXTURE_SEAL_HEX,
        &std.fmt.bytesToHex(manifest.seal, .lower),
    );
}

test "R-012 universal manifest binds every row size and fixed provider geometry" {
    const canonical = try manifest_mod.build(fixtureLogSizes());

    var changed = fixtureLogSizes();
    changed[@intFromEnum(roster.Component.transcript_air)] += 1;
    const changed_manifest = try manifest_mod.build(changed);
    try std.testing.expect(!std.mem.eql(u8, &canonical.seal, &changed_manifest.seal));

    // A stale row-20 projection cannot reuse the refreshed whole-roster seal,
    // even when every column count, offset, and log size remains unchanged.
    const query_row = @intFromEnum(roster.Component.query_bits);
    var semantic_drift = canonical;
    var query_placement = semantic_drift.placements[query_row].?;
    query_placement.geometry.semantic_digest[0] ^= 1;
    semantic_drift.placements[query_row] = query_placement;
    try std.testing.expectError(error.ManifestSealMismatch, semantic_drift.validate());

    var invalid = fixtureLogSizes();
    invalid[@intFromEnum(roster.Component.control)] = 0;
    try std.testing.expectError(error.InvalidLogSize, manifest_mod.build(invalid));

    invalid = fixtureLogSizes();
    invalid[@intFromEnum(roster.Component.poseidon2)] = 30;
    try std.testing.expectError(error.LogSizeMismatch, manifest_mod.build(invalid));

    invalid = fixtureLogSizes();
    invalid[@intFromEnum(roster.Component.range_check_8_8)] -= 1;
    try std.testing.expectError(error.LogSizeMismatch, manifest_mod.build(invalid));
}

fn fixtureLogSizes() manifest_mod.LogSizes {
    var result = [_]u32{4} ** roster.COMPONENT_COUNT;
    result[@intFromEnum(roster.Component.range_check_8_8)] = range_bridge.LOG_SIZE;
    return result;
}
