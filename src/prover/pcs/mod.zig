const std = @import("std");
const circle = @import("../../core/circle.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const pcs_core = @import("../../core/pcs/mod.zig");
const pcs_utils = @import("../../core/pcs/utils.zig");
const core_quotients = @import("../../core/pcs/quotients.zig");
const verifier_types = @import("../../core/verifier_types.zig");
const vcs_verifier = @import("../../core/vcs_lifted/verifier.zig");
const canonic = @import("../../core/poly/circle/canonic.zig");
const component_prover = @import("../air/component_prover.zig");
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const prover_fri = @import("../fri.zig");
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");

pub const quotient_ops = @import("quotient_ops.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PcsConfig = pcs_core.PcsConfig;
const TreeVec = pcs_core.TreeVec;
const TreeSubspan = pcs_core.TreeSubspan;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const PointSample = core_quotients.PointSample;

pub const CommitmentSchemeError = error{
    ShapeMismatch,
    InvalidPreprocessedTree,
    UnsupportedBlowup,
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

        /// Returns committed columns as prover-air `Poly` views.
        ///
        /// The returned wrappers borrow underlying column storage from the commitment scheme.
        pub fn polynomials(
            self: Self,
            allocator: std.mem.Allocator,
        ) !TreeVec([]component_prover.Poly) {
            const out = try allocator.alloc([]component_prover.Poly, self.trees.items.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |tree_polys| allocator.free(tree_polys);
            }

            for (self.trees.items, 0..) |tree, tree_idx| {
                const polys = try allocator.alloc(component_prover.Poly, tree.columns.len);
                out[tree_idx] = polys;
                initialized += 1;
                for (tree.columns, 0..) |column, col_idx| {
                    polys[col_idx] = .{
                        .log_size = column.log_size,
                        .values = column.values,
                    };
                }
            }
            return TreeVec([]component_prover.Poly).initOwned(out);
        }

        pub fn trace(
            self: Self,
            allocator: std.mem.Allocator,
        ) !component_prover.Trace {
            return .{
                .polys = try self.polynomials(allocator),
            };
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

        /// Proves sampled values for already-committed trees.
        ///
        /// Inputs:
        /// - `sampled_points`: per tree -> per column sampled points.
        ///
        /// Output:
        /// - full PCS opening proof with sampled values computed in-prover.
        ///
        /// Invariants:
        /// - sampled-point tree/column shape must match committed trees/columns.
        /// - every sampled point is folded to each column's log size before evaluation.
        pub fn proveValues(
            self: Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            channel: anytype,
        ) !pcs_core.ExtendedCommitmentSchemeProof(H) {
            var scheme = self;
            if (scheme.config.fri_config.log_blowup_factor != 0) {
                return CommitmentSchemeError.UnsupportedBlowup;
            }
            const lifting_log_size = try scheme.maxTreeLogSize();
            const sampled_values = try evaluateSampledValues(
                allocator,
                scheme.trees,
                sampled_points,
                lifting_log_size,
            );
            return scheme.proveValuesFromSamples(
                allocator,
                sampled_points,
                sampled_values,
                channel,
            );
        }

        /// Proves sampled values for already-committed trees using precomputed point evaluations.
        ///
        /// Inputs:
        /// - `sampled_points`: per tree -> per column sampled points.
        /// - `sampled_values`: per tree -> per column sampled values (same shape as points).
        ///
        /// Invariants:
        /// - `sampled_points` and `sampled_values` must match the tree/column shape.
        /// - Values are assumed to match the committed columns at those points.
        pub fn proveValuesFromSamples(
            self: Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            channel: anytype,
        ) !pcs_core.ExtendedCommitmentSchemeProof(H) {
            var scheme = self;
            defer scheme.deinit(allocator);

            if (scheme.config.fri_config.log_blowup_factor != 0) {
                return CommitmentSchemeError.UnsupportedBlowup;
            }

            if (scheme.trees.items.len != sampled_points.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }
            if (scheme.trees.items.len != sampled_values.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }

            for (scheme.trees.items, sampled_points.items, sampled_values.items) |tree, tree_points, tree_values| {
                if (tree.columns.len != tree_points.len) return CommitmentSchemeError.ShapeMismatch;
                if (tree.columns.len != tree_values.len) return CommitmentSchemeError.ShapeMismatch;
            }

            const sampled_values_flat = try flattenSampledValues(allocator, sampled_values);
            defer allocator.free(sampled_values_flat);
            channel.mixFelts(sampled_values_flat);
            const random_coeff = channel.drawSecureFelt();

            const lifting_log_size = try scheme.maxTreeLogSize();
            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

            var samples = try buildPointSamples(allocator, sampled_points, sampled_values);
            defer samples.deinitDeep(allocator);

            var borrowed_columns = try borrowedColumnsTree(allocator, scheme.trees);
            defer borrowed_columns.deinitDeep(allocator);

            const quotients_column = try quotient_ops.computeFriQuotients(
                allocator,
                borrowed_columns,
                samples,
                random_coeff,
                lifting_log_size,
                scheme.config.fri_config.log_blowup_factor,
            );

            var fri_prover = try prover_fri.FriProver(H, MC).commit(
                allocator,
                channel,
                scheme.config.fri_config,
                domain,
                quotients_column,
            );

            const proof_of_work = grind(channel, scheme.config.pow_bits);
            channel.mixU64(proof_of_work);

            var fri_decommit = try fri_prover.decommit(allocator, channel);
            errdefer fri_decommit.deinit(allocator);

            var query_positions_tree = try scheme.buildQueryPositionsTree(
                allocator,
                fri_decommit.query_positions,
                lifting_log_size,
            );
            defer query_positions_tree.deinitDeep(allocator);

            const query_positions_const = try allocator.alloc([]const usize, query_positions_tree.items.len);
            defer allocator.free(query_positions_const);
            for (query_positions_tree.items, 0..) |positions, i| {
                query_positions_const[i] = positions;
            }

            var trace_decommit = try scheme.decommitByTreePositions(
                allocator,
                TreeVec([]const usize).initOwned(query_positions_const),
            );
            errdefer trace_decommit.deinit(allocator);

            var commitments = try scheme.roots(allocator);
            errdefer commitments.deinit(allocator);

            return .{
                .proof = .{
                    .config = scheme.config,
                    .commitments = commitments,
                    .sampled_values = sampled_values,
                    .decommitments = trace_decommit.decommitments,
                    .queried_values = trace_decommit.queried_values,
                    .proof_of_work = proof_of_work,
                    .fri_proof = fri_decommit.fri_proof.proof,
                },
                .aux = .{
                    .unsorted_query_locations = fri_decommit.unsorted_query_locations,
                    .trace_decommitment = trace_decommit.aux,
                    .fri = fri_decommit.fri_proof.aux,
                },
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

        fn maxTreeLogSize(self: Self) !u32 {
            if (self.trees.items.len == 0) return CommitmentSchemeError.ShapeMismatch;
            var max_size: u32 = 0;
            for (self.trees.items) |tree| {
                max_size = @max(max_size, maxLogSize(tree.columns));
            }
            return max_size;
        }

        fn evaluateSampledValues(
            allocator: std.mem.Allocator,
            trees: TreeVec(CommitmentTreeProver(H)),
            sampled_points: TreeVec([][]CirclePointQM31),
            lifting_log_size: u32,
        ) !TreeVec([][]QM31) {
            if (trees.items.len != sampled_points.items.len) return CommitmentSchemeError.ShapeMismatch;

            const out = try allocator.alloc([][]QM31, trees.items.len);
            errdefer allocator.free(out);

            var initialized_trees: usize = 0;
            errdefer {
                for (out[0..initialized_trees]) |tree_values| {
                    for (tree_values) |column_values| allocator.free(column_values);
                    allocator.free(tree_values);
                }
            }

            for (trees.items, sampled_points.items, 0..) |tree, tree_points, tree_idx| {
                if (tree.columns.len != tree_points.len) return CommitmentSchemeError.ShapeMismatch;

                const tree_values = try allocator.alloc([]QM31, tree.columns.len);
                out[tree_idx] = tree_values;
                initialized_trees += 1;

                var initialized_columns: usize = 0;
                errdefer {
                    for (tree_values[0..initialized_columns]) |column_values| allocator.free(column_values);
                    allocator.free(tree_values);
                }

                for (tree.columns, tree_points, 0..) |column, points, col_idx| {
                    if (column.log_size > lifting_log_size) return CommitmentSchemeError.ShapeMismatch;
                    try column.validate();

                    const eval_domain = canonic.CanonicCoset.new(column.log_size).circleDomain();
                    const evaluation = try prover_circle.CircleEvaluation.init(
                        eval_domain,
                        column.values,
                    );

                    const values = try allocator.alloc(QM31, points.len);
                    tree_values[col_idx] = values;
                    initialized_columns += 1;

                    const fold_count = lifting_log_size - column.log_size;
                    for (points, 0..) |point, i| {
                        values[i] = try evaluation.evalAtPoint(
                            allocator,
                            point.repeatedDouble(fold_count),
                        );
                    }
                }
            }

            return TreeVec([][]QM31).initOwned(out);
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

fn flattenSampledValues(
    allocator: std.mem.Allocator,
    sampled_values: TreeVec([][]QM31),
) ![]QM31 {
    var total: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| total += column.len;
    }

    const out = try allocator.alloc(QM31, total);
    var at: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| {
            @memcpy(out[at .. at + column.len], column);
            at += column.len;
        }
    }
    return out;
}

fn buildPointSamples(
    allocator: std.mem.Allocator,
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
) (std.mem.Allocator.Error || CommitmentSchemeError)!TreeVec([][]PointSample) {
    if (sampled_points.items.len != sampled_values.items.len) return CommitmentSchemeError.ShapeMismatch;

    var trees = std.ArrayList([][]PointSample).init(allocator);
    defer trees.deinit();
    errdefer {
        for (trees.items) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
    }

    for (sampled_points.items, sampled_values.items) |points_tree, values_tree| {
        if (points_tree.len != values_tree.len) return CommitmentSchemeError.ShapeMismatch;

        var cols = std.ArrayList([]PointSample).init(allocator);
        defer cols.deinit();
        errdefer {
            for (cols.items) |column| allocator.free(column);
        }

        for (points_tree, values_tree) |points_col, values_col| {
            if (points_col.len != values_col.len) return CommitmentSchemeError.ShapeMismatch;
            const out_col = try allocator.alloc(PointSample, points_col.len);
            errdefer allocator.free(out_col);
            for (points_col, values_col, 0..) |point, value, i| {
                out_col[i] = .{
                    .point = point,
                    .value = value,
                };
            }
            try cols.append(out_col);
        }
        try trees.append(try cols.toOwnedSlice());
    }

    return TreeVec([][]PointSample).initOwned(try trees.toOwnedSlice());
}

fn borrowedColumnsTree(
    allocator: std.mem.Allocator,
    trees: anytype,
) !TreeVec([]ColumnEvaluation) {
    const tree_count = trees.items.len;
    const out = try allocator.alloc([]ColumnEvaluation, tree_count);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |tree_cols| allocator.free(tree_cols);
    }

    for (trees.items, 0..) |tree, i| {
        const cols = try allocator.alloc(ColumnEvaluation, tree.columns.len);
        out[i] = cols;
        initialized += 1;
        for (tree.columns, 0..) |column, j| {
            cols[j] = .{
                .log_size = column.log_size,
                .values = column.values,
            };
        }
    }

    return TreeVec([]ColumnEvaluation).initOwned(out);
}

fn grind(channel: anytype, pow_bits: u32) u64 {
    var nonce: u64 = 0;
    while (true) : (nonce += 1) {
        if (channel.verifyPowNonce(pow_bits, nonce)) return nonce;
    }
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

test "prover pcs: polynomials and trace expose committed columns" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var channel = Channel{};
    const tree0_col = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = tree0_col[0..] }},
        &channel,
    );

    var polys = try scheme.polynomials(alloc);
    defer polys.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), polys.items.len);
    try std.testing.expectEqual(@as(usize, 1), polys.items[0].len);
    try std.testing.expectEqual(@as(u32, 2), polys.items[0][0].log_size);
    try std.testing.expectEqualSlices(M31, tree0_col[0..], polys.items[0][0].values);

    var trace = try scheme.trace(alloc);
    defer trace.polys.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), trace.polys.items.len);
    try std.testing.expectEqualSlices(M31, tree0_col[0..], trace.polys.items[0][0].values);
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

test "prover pcs: prove values from samples roundtrip with core verifier" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(13);
    const sample_value = QM31.fromBase(M31.fromCanonical(5));

    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var extended_proof = try scheme.proveValuesFromSamples(
        alloc,
        sampled_points_prover,
        sampled_values,
        &prover_channel,
    );
    defer extended_proof.aux.deinit(alloc);

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_verify,
    });
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier_channel = Channel{};
    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);
    try verifier.commit(
        alloc,
        extended_proof.proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values computes sampled values in prover" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(73);
    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    var extended_proof = try scheme.proveValues(
        alloc,
        sampled_points_prover,
        &prover_channel,
    );
    defer extended_proof.aux.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items.len);
    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items[0][0].len);
    try std.testing.expect(extended_proof.proof.sampled_values.items[0][0][0].eql(
        QM31.fromBase(M31.fromCanonical(19)),
    ));

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_verify,
    });
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier_channel = Channel{};
    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);
    try verifier.commit(
        alloc,
        extended_proof.proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values from samples rejects shape mismatch" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 2),
    });
    defer scheme.deinit(alloc);

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    var channel = Channel{};
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );

    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(try alloc.alloc([][]CirclePointQM31, 0));
    const sampled_values = TreeVec([][]QM31).initOwned(try alloc.alloc([][]QM31, 0));
    try std.testing.expectError(
        CommitmentSchemeError.ShapeMismatch,
        scheme.proveValuesFromSamples(
            alloc,
            sampled_points,
            sampled_values,
            &channel,
        ),
    );
}

test "prover pcs: prove values paths reject unsupported blowup" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme_samples = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(1, 1, 2),
    });

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    var channel = Channel{};
    try scheme_samples.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(31);
    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col});
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{QM31.fromBase(M31.fromCanonical(5))});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    try std.testing.expectError(
        CommitmentSchemeError.UnsupportedBlowup,
        scheme_samples.proveValuesFromSamples(
            alloc,
            sampled_points,
            sampled_values,
            &channel,
        ),
    );

    var scheme_points = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(1, 1, 2),
    });
    try scheme_points.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );

    const sampled_points_col_only = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_only = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_only});
    const sampled_points_only = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_only}),
    );

    try std.testing.expectError(
        CommitmentSchemeError.UnsupportedBlowup,
        scheme_points.proveValues(
            alloc,
            sampled_points_only,
            &channel,
        ),
    );
}

test "prover pcs: inconsistent sampled values are rejected by fri degree check" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);
    defer scheme.deinit(alloc);

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(13);
    const bad_sample_value = QM31.fromBase(M31.fromCanonical(6));

    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col,
    });
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{bad_sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    try std.testing.expectError(
        prover_fri.FriProverError.InvalidLastLayerDegree,
        scheme.proveValuesFromSamples(
            alloc,
            sampled_points,
            sampled_values,
            &prover_channel,
        ),
    );
}

test "prover pcs: prove values rejects sampled point on domain" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;
    const canonic_domain = canonic.CanonicCoset.new(3).circleDomain();

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 3),
    });
    defer scheme.deinit(alloc);

    const column_values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        .{
            .x = QM31.fromBase(canonic_domain.at(0).x),
            .y = QM31.fromBase(canonic_domain.at(0).y),
        },
    });
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col,
    });
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    try std.testing.expectError(
        prover_circle_eval.EvaluationError.PointOnDomain,
        scheme.proveValues(alloc, sampled_points, &prover_channel),
    );
}
