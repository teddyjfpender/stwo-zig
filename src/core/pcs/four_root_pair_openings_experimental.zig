//! Experimental four-root Gate source-pair custody. The caller supplies the
//! four roots from its accepted transcript and raw query positions sampled
//! only after the new FRI commitments. This module does not draw challenges,
//! test polynomial degree, or define a production proof format.
const std = @import("std");
const m31 = @import("../fields/m31.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs = @import("../vcs_lifted/verifier.zig");

pub const H = blake2_merkle.Blake2sPlainMerkleHasher;
pub const M31 = m31.M31;
pub const root_count: usize = 4;
pub const composition_columns: usize = 8;

pub const Expected = struct {
    /// Fixed, main, interaction, composition, in that order. The transcript
    /// determines each root before this source-opening check is invoked.
    roots: [root_count]H.Hash,
    /// FRI-extended column logs, exactly as stored in native PCS trees.
    column_log_sizes: [root_count][]const u32,
    lifting_log_size: u32,
    raw_queries: []const usize,
};

pub const TreeOpening = struct {
    queried_values: [][]M31,
    hash_witness: []H.Hash,
};

pub fn pairPositions(
    allocator: std.mem.Allocator,
    raw_queries: []const usize,
    lifting_log_size: u32,
) ![]usize {
    if (lifting_log_size == 0 or lifting_log_size >= @bitSizeOf(usize) or
        raw_queries.len == 0) return error.InvalidFourRootPairShape;
    const domain_size: usize = @as(usize, 1) << @intCast(lifting_log_size);
    const count = std.math.mul(usize, raw_queries.len, 2) catch
        return error.InvalidFourRootPairShape;
    const positions = try allocator.alloc(usize, count);
    errdefer allocator.free(positions);
    for (raw_queries, 0..) |raw, i| {
        if (raw >= domain_size) return error.InvalidFourRootPairShape;
        positions[2 * i] = raw & ~@as(usize, 1);
        positions[2 * i + 1] = raw | 1;
    }
    return positions;
}

pub fn verify(
    allocator: std.mem.Allocator,
    expected: Expected,
    openings: [root_count]TreeOpening,
) !void {
    if (expected.column_log_sizes[3].len != composition_columns)
        return error.InvalidFourRootPairShape;
    const positions = try pairPositions(allocator, expected.raw_queries, expected.lifting_log_size);
    defer allocator.free(positions);
    for (expected.roots, expected.column_log_sizes, openings) |root, logs, opened| {
        if (logs.len == 0 or opened.queried_values.len != logs.len)
            return error.InvalidFourRootPairShape;
        for (logs) |log| {
            if (log < 1 or log > expected.lifting_log_size)
                return error.InvalidFourRootPairShape;
        }
        var tree = try vcs.MerkleVerifierLifted(H).initWithHeight(
            allocator,
            root,
            logs,
            expected.lifting_log_size,
        );
        defer tree.deinit(allocator);
        try tree.verify(allocator, positions, opened.queried_values, .{ .hash_witness = opened.hash_witness });
    }
}
