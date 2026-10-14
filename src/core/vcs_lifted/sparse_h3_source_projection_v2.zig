//! Candidate sparse Gate source projection for lifted Merkle leaves.
//!
//! A lower-height circle column is repeated into a top-height leaf while
//! preserving the sign bit. This module checks that geometry and the four
//! accepted H3 height buckets. It does not admit a proof: only the opaque
//! paired verifier may supply sampled raw queries and captured roots.
const std = @import("std");
const canonic = @import("../poly/circle/canonic.zig");
const utils = @import("../utils.zig");
const pcs_utils = @import("../pcs/utils.zig");
const m31 = @import("../fields/m31.zig");
const source_hash = @import("blake2s_personalized_source_v2.zig");
const lifted = @import("verifier.zig");

pub const source_tree_count = 4;
pub const max_source_columns = 256;
pub const accepted_h3_logs = [3]u32{ 17, 11, 5 };
pub const accepted_h3_counts = [source_tree_count]usize{ 12, 17, 24, 8 };
pub const Error = error{
    InvalidSourceHeight,
    InvalidRawQuery,
    InvalidAcceptedRoster,
    InvalidProjectedPair,
};

/// Native lifted leaf/decommit law. The low bit is the circle pair's sign
/// bit and must survive every descent; a plain `raw >> (k-h)` is wrong.
pub fn projectCircleRow(raw: usize, top_log: u32, source_log: u32) Error!usize {
    if (top_log < 2 or top_log > 30 or source_log < 1 or source_log > top_log)
        return error.InvalidSourceHeight;
    if (raw >= (@as(usize, 1) << @intCast(top_log)))
        return error.InvalidRawQuery;
    const shift: std.math.Log2Int(usize) = @intCast(top_log - source_log + 1);
    return ((raw >> shift) << 1) | (raw & 1);
}

pub fn projectCirclePair(raw: usize, top_log: u32, source_log: u32) Error![2]usize {
    const left = try projectCircleRow(raw & ~@as(usize, 1), top_log, source_log);
    const right = try projectCircleRow(raw | 1, top_log, source_log);
    if (left & 1 != 0 or right != left + 1 or
        right >= (@as(usize, 1) << @intCast(source_log)))
        return error.InvalidProjectedPair;
    return .{ left, right };
}

/// The currently accepted sparse Gate key has 61 source columns at 17/11/5.
/// The complete ordered height roster is checked, not merely bucket counts.
/// Column identities and mask offsets still come from the sealed key.
pub fn validateAcceptedH3Logs(logs: [source_tree_count][]const u32) Error!void {
    for (logs, accepted_h3_counts) |tree, count|
        if (tree.len != count) return error.InvalidAcceptedRoster;
    const ordered = [source_tree_count][]const u32{
        &.{ 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 17 },
        &.{ 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 17 },
        &.{ 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 17, 17, 17, 17 },
        &([_]u32{17} ** 8),
    };
    for (logs, ordered) |tree, want|
        if (!std.mem.eql(u32, tree, want)) return error.InvalidAcceptedRoster;
}

/// A bit-reversed circle query, doubled `top_log-source_log` times, must land
/// on the lower source row selected by `projectCircleRow`.
pub fn checkCircleProjection(raw: usize, top_log: u32, source_log: u32) Error!void {
    const projected = try projectCircleRow(raw, top_log, source_log);
    const top = canonic.CanonicCoset.new(top_log).circleDomain()
        .at(utils.bitReverseIndex(raw, top_log));
    const lower = canonic.CanonicCoset.new(source_log).circleDomain()
        .at(utils.bitReverseIndex(projected, source_log));
    if (!top.repeatedDouble(top_log - source_log).eql(lower))
        return error.InvalidProjectedPair;
}

test "accepted sparse H3 lower circle projection preserves adjacent sign pair" {
    const raw: usize = 90528;
    const at_17 = try projectCirclePair(raw, 17, 17);
    const at_11 = try projectCirclePair(raw, 17, 11);
    const at_5 = try projectCirclePair(raw, 17, 5);
    try std.testing.expectEqualDeep([2]usize{ 90528, 90529 }, at_17);
    try std.testing.expectEqualDeep([2]usize{ 1414, 1415 }, at_11);
    try std.testing.expectEqualDeep([2]usize{ 22, 23 }, at_5);
    for (accepted_h3_logs) |h| {
        try checkCircleProjection(raw, 17, h);
        try checkCircleProjection(raw + 1, 17, h);
        const native = try pcs_utils.prepareTreeQueryPositions(std.testing.allocator, &.{ raw, raw + 1 }, 17, h);
        defer std.testing.allocator.free(native);
        try std.testing.expectEqualDeep(try projectCirclePair(raw, 17, h), native[0..2].*);
    }
    // Different top queries may intentionally name the same lower pair.
    try std.testing.expectEqualDeep(at_5, try projectCirclePair(raw + 64, 17, 5));
    try std.testing.expectError(error.InvalidRawQuery, projectCircleRow(1 << 17, 17, 5));
    try std.testing.expectError(error.InvalidSourceHeight, projectCircleRow(0, 17, 18));
}

test "accepted H3 bucket counts reject mutated source roster" {
    const fixed = [_]u32{ 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 17 };
    const main = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 17 };
    const interaction = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 17, 17, 17, 17 };
    const composition = [_]u32{17} ** 8;
    try validateAcceptedH3Logs(.{ &fixed, &main, &interaction, &composition });
    var wrong = interaction;
    wrong[20] = 11;
    try std.testing.expectError(error.InvalidAcceptedRoster, validateAcceptedH3Logs(.{ &fixed, &main, &wrong, &composition }));
    var reordered = main;
    std.mem.swap(u32, &reordered[0], &reordered[12]);
    try std.testing.expectError(error.InvalidAcceptedRoster, validateAcceptedH3Logs(.{ &fixed, &reordered, &interaction, &composition }));
    try std.testing.expectError(error.InvalidAcceptedRoster, validateAcceptedH3Logs(.{ &fixed, &main, &interaction, composition[0..7] }));
}

test "mixed-height lifted pair paths reject wrong projected row and pair replay" {
    const M31 = m31.M31;
    const H = source_hash.SourceMerkleHasherV2;
    const allocator = std.testing.allocator;
    var lower: [8]M31 = undefined;
    var top: [32]M31 = undefined;
    for (&lower, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(200 + i));
    for (&top, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(100 + i));
    var levels: [6][32]H.Hash = undefined;
    for (0..32) |pos| {
        var hasher = H.defaultWithInitialState();
        hasher.updateLeaf(lower[(try projectCircleRow(pos, 5, 3))..][0..1]);
        hasher.updateLeaf(top[pos..][0..1]);
        levels[0][pos] = hasher.finalize();
    }
    for (1..6) |level| for (0..(@as(usize, 32) >> @intCast(level))) |i| {
        levels[level][i] = H.hashChildren(.{
            .left = levels[level - 1][2 * i],
            .right = levels[level - 1][2 * i + 1],
        });
    };
    var logs = [_]u32{ 5, 3 };
    const verifier = lifted.MerkleVerifierLifted(H){
        .root = levels[5][0],
        .column_log_sizes = &logs,
        .height = 5,
    };
    var previous_top: [2]M31 = undefined;
    var previous_lower: [2]M31 = undefined;
    var previous_witness: [4]H.Hash = undefined;
    for ([_]usize{ 12, 14 }, 0..) |base, ordinal| {
        const projected = try projectCirclePair(base, 5, 3);
        var opened_top = [2]M31{ top[base], top[base + 1] };
        var opened_lower = [2]M31{ lower[projected[0]], lower[projected[1]] };
        var witness: [4]H.Hash = undefined;
        for (&witness, 1..) |*sibling, level|
            sibling.* = levels[level][(base >> @intCast(level)) ^ 1];
        const positions = [2]usize{ base, base + 1 };
        const rows = [2][]const M31{ &opened_top, &opened_lower };
        try verifier.verify(allocator, &positions, &rows, .{ .hash_witness = &witness });
        if (ordinal == 0) {
            previous_top = opened_top;
            previous_lower = opened_lower;
            previous_witness = witness;
        }
        opened_lower[0] = M31.fromCanonical(999);
        const wrong_rows = [2][]const M31{ &opened_top, &opened_lower };
        try std.testing.expectError(error.RootMismatch, verifier.verify(allocator, &positions, &wrong_rows, .{ .hash_witness = &witness }));
    }
    try std.testing.expectEqualDeep(try projectCirclePair(12, 5, 3), try projectCirclePair(14, 5, 3));
    const wrong_positions = [2]usize{ 14, 15 };
    const replay_rows = [2][]const M31{ &previous_top, &previous_lower };
    try std.testing.expectError(error.RootMismatch, verifier.verify(allocator, &wrong_positions, &replay_rows, .{ .hash_witness = &previous_witness }));
}
