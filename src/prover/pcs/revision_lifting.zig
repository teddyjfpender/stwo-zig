//! Commitment heights of the `proving_5a7c5ed` protocol revision.
//!
//! Upstream (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, `crates/stwo/src/prover/pcs`)
//! commits tree `i` at `PcsConfig::lifting_log_size(i)`, which may exceed the
//! tree's largest column, and proves at the height of the last committed
//! tree. The existing lanes commit every tree at its largest column.
//!
//! A scheme whose Merkle channel is of this revision takes its heights with
//! `CommitmentSchemeProver.initRevision` or `setRevisionConfig`. Every
//! commit path (owned, streaming, cached, deferred, arena-backed) still builds
//! its tree at the natural height; the scheme lifts the finished tree here,
//! once, before its root is mixed (`tree_builders.appendCommittedTree`,
//! `deferred_commit.resolveObserved`). A lifted leaf is the natural leaf at the
//! lifted index, so lifting rehashes nodes only and never reads a column.
//!
//! Backend contract: a backend whose Merkle tree is the host
//! `MerkleProverLifted` is lifted with `MerkleProverLifted.liftTo`; any other
//! backend must declare
//! `liftMerkle(comptime H, allocator, *MerkleTree(H), lifting_log_size) !void`
//! or the scheme refuses the tree (`error.UnsupportedLiftedCommitment`)
//! instead of committing it at a different height.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");

pub const PcsConfigV2 = pcs_core.config_v2.PcsConfigV2;
pub const FriConfigV2 = pcs_core.config_v2.FriConfigV2;

pub const Error = error{UnsupportedLiftedCommitment};

/// Lifts `tree` (about to become tree `tree_index`) to its configured height.
/// Fail-atomic: on error the tree and its commitment are unchanged.
pub fn liftCommittedTree(
    comptime B: type,
    comptime H: type,
    config: PcsConfigV2,
    allocator: std.mem.Allocator,
    tree: anytype,
    tree_index: usize,
) !void {
    const log_sizes = try allocator.alloc(u32, tree.columns.len);
    defer allocator.free(log_sizes);
    for (tree.columns, log_sizes) |column, *log_size| log_size.* = column.log_size;
    const height = try config.treeHeight(tree_index, log_sizes);
    if (height == tree.commitment.maxLogSize()) return;
    // A shared tree is a lease on storage other proofs read; lifting it would
    // change their commitment.
    if (tree.shared_owner != null) return Error.UnsupportedLiftedCommitment;
    if (comptime @hasDecl(B, "recommitMerkleLifted")) {
        const columns = try allocator.alloc([]const @import("stwo_core").fields.m31.M31, tree.columns.len);
        defer allocator.free(columns);
        for (tree.columns, columns) |column, *values| {
            if (column.values.len != @as(usize, 1) << @intCast(column.log_size))
                return Error.UnsupportedLiftedCommitment;
            values.* = column.values;
        }
        var lifted = try B.recommitMerkleLifted(H, allocator, columns, height);
        errdefer lifted.deinit(allocator);
        tree.commitment.deinit(allocator);
        tree.commitment = lifted;
    } else if (comptime @hasDecl(B, "liftMerkle")) {
        return B.liftMerkle(H, allocator, &tree.commitment, height);
    } else if (comptime B.MerkleTree(H) == vcs_lifted_prover.MerkleProverLifted(H)) {
        tree.commitment.liftTo(allocator, height) catch |err| switch (err) {
            // Large trees drop their bottom layers after committing
            // (`compactForQueries`); rebuild from the retained columns.
            error.InvalidColumnSize => return recommitLifted(H, allocator, tree, height),
            else => return err,
        };
    } else {
        return Error.UnsupportedLiftedCommitment;
    }
}

/// Commits `tree`'s columns afresh at `height`. The result keeps every layer:
/// pruned-leaf query reconstruction addresses the largest column's height
/// only, so a lifted tree is never compacted.
fn recommitLifted(comptime H: type, allocator: std.mem.Allocator, tree: anytype, height: u32) !void {
    const Tree = vcs_lifted_prover.MerkleProverLifted(H);
    const columns = try allocator.alloc([]const @import("stwo_core").fields.m31.M31, tree.columns.len);
    defer allocator.free(columns);
    for (tree.columns, columns) |column, *values| {
        if (column.values.len != @as(usize, 1) << @intCast(column.log_size)) return Error.UnsupportedLiftedCommitment;
        values.* = column.values;
    }
    var lifted = try Tree.commitLifted(allocator, columns, height);
    errdefer lifted.deinit(allocator);
    tree.commitment.deinit(allocator);
    tree.commitment = lifted;
}

/// `max_log_degree_bound` of `prove_ex` under the revision: the last tree's
/// height minus the blowup. With `include_all_preprocessed_columns` that
/// height may not be below the preprocessed tree's
/// (`InvalidLiftingLogSizeError`).
pub fn maskLogSize(
    config: PcsConfigV2,
    final_tree_height: u32,
    preprocessed_tree_height: u32,
    include_all_preprocessed_columns: bool,
) PcsConfigV2.Error!u32 {
    if (include_all_preprocessed_columns and final_tree_height < preprocessed_tree_height)
        return error.InvalidLiftingLogSize;
    if (final_tree_height <= config.fri_config.log_blowup_factor) return error.InvalidLiftingLogSize;
    return final_tree_height - config.fri_config.log_blowup_factor;
}

test "revision lifting: mask log size follows the final tree" {
    const config = PcsConfigV2.fromFriAndLiftingSize(try FriConfigV2.init(16, 0, 1, 70, 1), 21);
    try std.testing.expectEqual(@as(u32, 20), try maskLogSize(config, 21, 21, true));
    try std.testing.expectError(error.InvalidLiftingLogSize, maskLogSize(config, 20, 21, true));
    try std.testing.expectEqual(@as(u32, 19), try maskLogSize(config, 20, 21, false));
}

const HostBackend = struct {
    pub const reuses_constant_merkle_parents = true;
    pub fn MerkleTree(comptime Hasher: type) type {
        return vcs_lifted_prover.MerkleProverLifted(Hasher);
    }
    pub fn commitMerkle(
        comptime Hasher: type,
        allocator: std.mem.Allocator,
        columns: []const []const @import("stwo_core").fields.m31.M31,
    ) !MerkleTree(Hasher) {
        return MerkleTree(Hasher).commit(allocator, columns);
    }
};

test "revision lifting: a committed tree equals the tree committed at its height" {
    // 2^20 leaves exercise the pruned path: the committed tree drops its
    // bottom layers (`compactForQueries`) and is rebuilt from its columns.
    const M31 = @import("stwo_core").fields.m31.M31;
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
    const Tree = @import("commitment_tree.zig").CommitmentTreeProverForBackend(HostBackend, H);
    const Merkle = vcs_lifted_prover.MerkleProverLifted(H);
    const allocator = std.testing.allocator;
    const fri = try FriConfigV2.init(0, 0, 1, 3, 1);
    inline for (.{ .{ 5, 7 }, .{ 20, 21 } }) |case| {
        const log_size: u32 = case[0];
        const height: u32 = case[1];
        const columns = try allocator.alloc(@import("commitment_tree.zig").ColumnEvaluation, 2);
        for (columns, [_]u32{ log_size, log_size - 2 }, 0..) |*column, column_log, salt| {
            const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(column_log));
            for (values, 0..) |*value, row| value.* = M31.fromU64(@as(u64, row) * row + 7 * salt + 3);
            column.* = .{ .log_size = column_log, .values = values };
        }
        var expected = try Merkle.commitLifted(allocator, &.{ columns[0].values, columns[1].values }, height);
        defer expected.deinit(allocator);
        var tree = try Tree.initOwned(allocator, columns);
        defer tree.deinit(allocator);

        const config = PcsConfigV2.fromFriAndLiftingSize(fri, height);
        try liftCommittedTree(HostBackend, H, config, allocator, &tree, 1);
        try std.testing.expectEqual(height, tree.commitment.maxLogSize());
        try std.testing.expectEqualSlices(u8, &expected.root(), &tree.root());

        const positions = [_]usize{ 0, 5, 6, (@as(usize, 1) << @intCast(height)) - 1 };
        var opened = try tree.decommit(allocator, &positions);
        defer opened.deinit(allocator);
        var direct = try expected.decommit(allocator, &positions, &.{ columns[0].values, columns[1].values });
        defer direct.deinit(allocator);
        const witness = opened.decommitment.decommitment.hash_witness;
        try std.testing.expectEqual(direct.decommitment.decommitment.hash_witness.len, witness.len);
        for (witness, direct.decommitment.decommitment.hash_witness) |a, b| try std.testing.expectEqualSlices(u8, &b, &a);
        for (opened.queried_values, direct.queried_values) |a, b| try std.testing.expectEqualSlices(M31, b, a);

        // A height below the committed columns is refused and changes nothing.
        const root = tree.root();
        const short = PcsConfigV2.fromFriAndLiftingSize(fri, log_size - 1);
        try std.testing.expectError(error.InvalidTreeHeight, liftCommittedTree(HostBackend, H, short, allocator, &tree, 1));
        try std.testing.expectEqualSlices(u8, &root, &tree.root());
    }
}
