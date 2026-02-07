const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const pcs_core = @import("../../core/pcs/mod.zig");
const pcs_utils = @import("../../core/pcs/utils.zig");
const verifier_types = @import("../../core/verifier_types.zig");
const vcs_verifier = @import("../../core/vcs_lifted/verifier.zig");
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");

pub const quotient_ops = @import("quotient_ops.zig");

const M31 = m31.M31;
const PcsConfig = pcs_core.PcsConfig;
const TreeVec = pcs_core.TreeVec;
const TreeSubspan = pcs_core.TreeSubspan;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;

pub const CommitmentSchemeError = error{
    ShapeMismatch,
    InvalidPreprocessedTree,
};

pub const ColumnEvaluation = quotient_ops.ColumnEvaluation;

pub fn CommitmentTreeProver(comptime H: type) type {
    return struct {
        columns: []ColumnEvaluation,
        commitment: vcs_lifted_prover.MerkleProverLifted(H),

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
        ) !Self {
            const owned_columns = try cloneColumnsOwned(allocator, columns);
            errdefer freeOwnedColumns(allocator, owned_columns);
            return initOwned(allocator, owned_columns);
        }

        pub fn initOwned(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
        ) !Self {
            for (owned_columns) |column| try column.validate();

            const column_refs = try allocator.alloc([]const M31, owned_columns.len);
            defer allocator.free(column_refs);
            for (owned_columns, 0..) |column, i| {
                column_refs[i] = column.values;
            }

            var commitment = try vcs_lifted_prover.MerkleProverLifted(H).commit(
                allocator,
                column_refs,
            );
            errdefer commitment.deinit(allocator);

            return .{
                .columns = owned_columns,
                .commitment = commitment,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            freeOwnedColumns(allocator, self.columns);
            self.commitment.deinit(allocator);
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return self.commitment.root();
        }

        pub fn columnLogSizes(self: Self, allocator: std.mem.Allocator) ![]u32 {
            const out = try allocator.alloc(u32, self.columns.len);
            for (self.columns, 0..) |column, i| out[i] = column.log_size;
            return out;
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
        ) !vcs_lifted_prover.MerkleProverLifted(H).DecommitmentResult {
            const column_refs = try allocator.alloc([]const M31, self.columns.len);
            defer allocator.free(column_refs);
            for (self.columns, 0..) |column, i| {
                column_refs[i] = column.values;
            }
            return self.commitment.decommit(allocator, query_positions, column_refs);
        }

        fn cloneColumnsOwned(
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
        ) ![]ColumnEvaluation {
            const owned = try allocator.alloc(ColumnEvaluation, columns.len);
            errdefer allocator.free(owned);

            var initialized: usize = 0;
            errdefer {
                for (owned[0..initialized]) |column| allocator.free(column.values);
            }

            for (columns, 0..) |column, i| {
                owned[i] = .{
                    .log_size = column.log_size,
                    .values = try allocator.dupe(M31, column.values),
                };
                initialized += 1;
            }

            return owned;
        }

        fn freeOwnedColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
            for (columns) |column| allocator.free(column.values);
            allocator.free(columns);
        }
    };
}

pub fn TreeDecommitmentResult(comptime H: type) type {
    return struct {
        queried_values: TreeVec([][]M31),
        decommitments: TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)),
        aux: TreeVec(vcs_verifier.MerkleDecommitmentLiftedAux(H)),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.queried_values.deinitDeep(allocator);
            for (self.decommitments.items) |*d| d.deinit(allocator);
            self.decommitments.deinit(allocator);
            for (self.aux.items) |*a| a.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn CommitmentSchemeProver(comptime H: type, comptime MC: type) type {
    return struct {
        trees: TreeVec(CommitmentTreeProver(H)),
        config: PcsConfig,
        store_polynomials_coefficients: bool,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, config: PcsConfig) !Self {
            return .{
                .trees = TreeVec(CommitmentTreeProver(H)).initOwned(
                    try allocator.alloc(CommitmentTreeProver(H), 0),
                ),
                .config = config,
                .store_polynomials_coefficients = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.trees.items) |*tree| tree.deinit(allocator);
            self.trees.deinit(allocator);
            self.* = undefined;
        }

        pub fn setStorePolynomialsCoefficients(self: *Self) void {
            self.store_polynomials_coefficients = true;
        }

        pub fn commit(
            self: *Self,
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
            channel: anytype,
        ) !void {
            var tree = try CommitmentTreeProver(H).init(allocator, columns);
            errdefer tree.deinit(allocator);
            try self.appendCommittedTree(allocator, tree, channel);
        }

        pub fn treeBuilder(self: *Self, allocator: std.mem.Allocator) TreeBuilder(H, MC) {
            return .{
                .allocator = allocator,
                .tree_index = self.trees.items.len,
                .commitment_scheme = self,
                .columns = std.ArrayList(ColumnEvaluation).init(allocator),
            };
        }

        pub fn roots(self: Self, allocator: std.mem.Allocator) !TreeVec(H.Hash) {
            const out = try allocator.alloc(H.Hash, self.trees.items.len);
            for (self.trees.items, 0..) |tree, i| {
                out[i] = tree.root();
            }
            return TreeVec(H.Hash).initOwned(out);
        }

        pub fn columnLogSizes(self: Self, allocator: std.mem.Allocator) !TreeVec([]u32) {
            const out = try allocator.alloc([]u32, self.trees.items.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
            }

            for (self.trees.items, 0..) |tree, i| {
                out[i] = try tree.columnLogSizes(allocator);
                initialized += 1;
            }

            return TreeVec([]u32).initOwned(out);
        }

        pub fn buildQueryPositionsTree(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            lifting_log_size: u32,
        ) !TreeVec([]usize) {
            const out = try allocator.alloc([]usize, self.trees.items.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |positions| allocator.free(positions);
            }

            const pp_max_log_size = if (self.trees.items.len > PREPROCESSED_TRACE_IDX)
                maxLogSize(self.trees.items[PREPROCESSED_TRACE_IDX].columns)
            else
                return CommitmentSchemeError.InvalidPreprocessedTree;

            const preprocessed_positions = try pcs_utils.preparePreprocessedQueryPositions(
                allocator,
                query_positions,
                lifting_log_size,
                pp_max_log_size,
            );
            defer allocator.free(preprocessed_positions);

            for (0..self.trees.items.len) |tree_idx| {
                if (tree_idx == PREPROCESSED_TRACE_IDX) {
                    out[tree_idx] = try allocator.dupe(usize, preprocessed_positions);
                } else {
                    out[tree_idx] = try allocator.dupe(usize, query_positions);
                }
                initialized += 1;
            }

            return TreeVec([]usize).initOwned(out);
        }

        pub fn decommitByTreePositions(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions_tree: TreeVec([]const usize),
        ) !TreeDecommitmentResult(H) {
            if (query_positions_tree.items.len != self.trees.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }

            const queried_values_out = try allocator.alloc([][]M31, self.trees.items.len);
            errdefer allocator.free(queried_values_out);
            const decommitments_out = try allocator.alloc(vcs_verifier.MerkleDecommitmentLifted(H), self.trees.items.len);
            errdefer allocator.free(decommitments_out);
            const aux_out = try allocator.alloc(vcs_verifier.MerkleDecommitmentLiftedAux(H), self.trees.items.len);
            errdefer allocator.free(aux_out);

            var initialized: usize = 0;
            errdefer {
                for (queried_values_out[0..initialized]) |tree_values| {
                    for (tree_values) |col| allocator.free(col);
                    allocator.free(tree_values);
                }
                for (decommitments_out[0..initialized]) |*d| d.deinit(allocator);
                for (aux_out[0..initialized]) |*a| a.deinit(allocator);
            }

            for (self.trees.items, query_positions_tree.items, 0..) |tree, positions, i| {
                const decommit = try tree.decommit(allocator, positions);
                queried_values_out[i] = decommit.queried_values;
                decommitments_out[i] = decommit.decommitment.decommitment;
                aux_out[i] = decommit.decommitment.aux;
                initialized += 1;
            }

            return .{
                .queried_values = TreeVec([][]M31).initOwned(queried_values_out),
                .decommitments = TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(decommitments_out),
                .aux = TreeVec(vcs_verifier.MerkleDecommitmentLiftedAux(H)).initOwned(aux_out),
            };
        }

        fn appendCommittedTree(
            self: *Self,
            allocator: std.mem.Allocator,
            tree: CommitmentTreeProver(H),
            channel: anytype,
        ) !void {
            MC.mixRoot(channel, tree.root());

            const old_len = self.trees.items.len;
            const out = try allocator.alloc(CommitmentTreeProver(H), old_len + 1);
            errdefer allocator.free(out);

            @memcpy(out[0..old_len], self.trees.items);
            out[old_len] = tree;

            allocator.free(self.trees.items);
            self.trees.items = out;
        }

        fn maxLogSize(columns: []const ColumnEvaluation) u32 {
            var max_size: u32 = 0;
            for (columns) |column| max_size = @max(max_size, column.log_size);
            return max_size;
        }
    };
}

pub fn TreeBuilder(comptime H: type, comptime MC: type) type {
    return struct {
        allocator: std.mem.Allocator,
        tree_index: usize,
        commitment_scheme: *CommitmentSchemeProver(H, MC),
        columns: std.ArrayList(ColumnEvaluation),

        const Self = @This();

        pub fn deinit(self: *Self) void {
            for (self.columns.items) |column| self.allocator.free(column.values);
            self.columns.deinit();
            self.* = undefined;
        }

        pub fn extendColumns(self: *Self, cols: []const ColumnEvaluation) !TreeSubspan {
            const col_start = self.columns.items.len;
            for (cols) |column| {
                try column.validate();
                try self.columns.append(.{
                    .log_size = column.log_size,
                    .values = try self.allocator.dupe(M31, column.values),
                });
            }
            const col_end = self.columns.items.len;
            return .{
                .tree_index = self.tree_index,
                .col_start = col_start,
                .col_end = col_end,
            };
        }

        pub fn commit(self: *Self, channel: anytype) !void {
            const owned = try self.columns.toOwnedSlice();
            self.columns = std.ArrayList(ColumnEvaluation).init(self.allocator);
            errdefer {
                for (owned) |column| self.allocator.free(column.values);
                self.allocator.free(owned);
            }

            var tree = try CommitmentTreeProver(H).initOwned(self.allocator, owned);
            errdefer tree.deinit(self.allocator);
            try self.commitment_scheme.appendCommittedTree(self.allocator, tree, channel);
        }
    };
}

test "prover pcs: commitment tree decommit verifies" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Verifier = vcs_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const col0 = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    const col1 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
    };

    var tree = try CommitmentTreeProver(Hasher).init(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 2, .values = col1[0..] },
        },
    );
    defer tree.deinit(alloc);

    const queries = [_]usize{ 1, 3, 6 };
    var decommit = try tree.decommit(alloc, queries[0..]);
    defer decommit.deinit(alloc);

    const log_sizes = try tree.columnLogSizes(alloc);
    defer alloc.free(log_sizes);

    var verifier = try Verifier.init(alloc, tree.root(), log_sizes);
    defer verifier.deinit(alloc);

    try verifier.verify(
        alloc,
        queries[0..],
        decommit.queried_values,
        decommit.decommitment.decommitment,
    );
}

test "prover pcs: commitment scheme commit, roots and log sizes" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var channel = Channel{};
    const before = channel.digestBytes();

    const tree0_col = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = tree0_col[0..] }},
        &channel,
    );

    const tree1_col = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = tree1_col[0..] }},
        &channel,
    );

    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
    try std.testing.expectEqual(@as(usize, 2), scheme.trees.items.len);

    var roots = try scheme.roots(alloc);
    defer roots.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), roots.items.len);

    var sizes = try scheme.columnLogSizes(alloc);
    defer sizes.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 2), sizes.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{2}, sizes.items[0]);
    try std.testing.expectEqualSlices(u32, &[_]u32{2}, sizes.items[1]);
}

test "prover pcs: tree builder extends and commits" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var builder = scheme.treeBuilder(alloc);
    defer builder.deinit();

    const col0 = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    const col1 = [_]M31{ M31.fromCanonical(11), M31.fromCanonical(12), M31.fromCanonical(13), M31.fromCanonical(14) };

    const span0 = try builder.extendColumns(
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = col0[0..] }},
    );
    try std.testing.expectEqual(@as(usize, 0), span0.tree_index);
    try std.testing.expectEqual(@as(usize, 0), span0.col_start);
    try std.testing.expectEqual(@as(usize, 1), span0.col_end);

    const span1 = try builder.extendColumns(
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = col1[0..] }},
    );
    try std.testing.expectEqual(@as(usize, 1), span1.col_start);
    try std.testing.expectEqual(@as(usize, 2), span1.col_end);

    var channel = Channel{};
    try builder.commit(&channel);

    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items.len);
    try std.testing.expectEqual(@as(usize, 2), scheme.trees.items[0].columns.len);
}

test "prover pcs: build query positions tree applies preprocessed mapping" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var channel = Channel{};

    const pp_col = [_]M31{ M31.one(), M31.one(), M31.one(), M31.one() };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = pp_col[0..] }},
        &channel,
    );

    const main_col = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 3, .values = main_col[0..] }},
        &channel,
    );

    const query_positions = [_]usize{ 0, 1, 5, 6 };
    var tree_queries = try scheme.buildQueryPositionsTree(alloc, query_positions[0..], 3);
    defer tree_queries.deinitDeep(alloc);

    const expected_pp = try pcs_utils.preparePreprocessedQueryPositions(
        alloc,
        query_positions[0..],
        3,
        2,
    );
    defer alloc.free(expected_pp);

    try std.testing.expectEqual(@as(usize, 2), tree_queries.items.len);
    try std.testing.expectEqualSlices(usize, expected_pp, tree_queries.items[0]);
    try std.testing.expectEqualSlices(usize, query_positions[0..], tree_queries.items[1]);
}

test "prover pcs: decommit by tree positions verifies" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = vcs_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var channel = Channel{};

    const tree0 = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = tree0[0..] }},
        &channel,
    );

    const tree1 = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
        M31.fromCanonical(13),
        M31.fromCanonical(14),
        M31.fromCanonical(15),
        M31.fromCanonical(16),
        M31.fromCanonical(17),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 3, .values = tree1[0..] }},
        &channel,
    );

    const tree0_queries = try alloc.dupe(usize, &[_]usize{ 0, 3 });
    const tree1_queries = try alloc.dupe(usize, &[_]usize{ 1, 6 });
    var query_tree = TreeVec([]const usize).initOwned(
        try alloc.dupe([]const usize, &[_][]const usize{ tree0_queries, tree1_queries }),
    );
    defer query_tree.deinitDeep(alloc);

    var decommit = try scheme.decommitByTreePositions(alloc, query_tree);
    defer decommit.deinit(alloc);

    var sizes = try scheme.columnLogSizes(alloc);
    defer sizes.deinitDeep(alloc);

    var verifier0 = try Verifier.init(alloc, scheme.trees.items[0].root(), sizes.items[0]);
    defer verifier0.deinit(alloc);
    try verifier0.verify(
        alloc,
        tree0_queries,
        decommit.queried_values.items[0],
        decommit.decommitments.items[0],
    );

    var verifier1 = try Verifier.init(alloc, scheme.trees.items[1].root(), sizes.items[1]);
    defer verifier1.deinit(alloc);
    try verifier1.verify(
        alloc,
        tree1_queries,
        decommit.queried_values.items[1],
        decommit.decommitments.items[1],
    );
}
