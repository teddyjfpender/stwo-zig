const std = @import("std");
const builtin = @import("builtin");
const circle = @import("../../core/circle.zig");
const channel_blake2s = @import("../../core/channel/blake2s.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const pcs_core = @import("../../core/pcs/mod.zig");
const pcs_utils = @import("../../core/pcs/utils.zig");
const core_quotients = @import("../../core/pcs/quotients.zig");
const verifier_types = @import("../../core/verifier_types.zig");
const blake2_hash = @import("../../core/vcs/blake2_hash.zig");
const vcs_verifier = @import("../../core/vcs_lifted/verifier.zig");
const canonic = @import("../../core/poly/circle/canonic.zig");
const component_prover = @import("../air/component_prover.zig");
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const stage_profile = @import("../stage_profile.zig");
const twiddles_mod = @import("../poly/twiddles.zig");
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
const COEFFICIENT_STORAGE_AUTO_MAX_BYTES: usize = 8 * 1024 * 1024;
const FFT_BATCH_TARGET_BYTES: usize = 256 * 1024;

pub const CommitmentSchemeError = error{
    ShapeMismatch,
    InvalidPreprocessedTree,
};

const CoefficientRetentionPolicy = enum {
    auto,
    always,
    never,
};

pub const ColumnEvaluation = quotient_ops.ColumnEvaluation;

pub fn CommitmentTreeProver(comptime H: type) type {
    return struct {
        columns: []ColumnEvaluation,
        coefficients: ?[]prover_circle.CircleCoefficients,
        commitment: vcs_lifted_prover.MerkleProverLifted(H),

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
        ) !Self {
            const owned_columns = try cloneColumnsOwned(allocator, columns);
            errdefer freeOwnedColumns(allocator, owned_columns);
            return initOwnedWithCoefficients(allocator, owned_columns, null);
        }

        pub fn initOwned(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
        ) !Self {
            return initOwnedWithCoefficients(allocator, owned_columns, null);
        }

        pub fn initOwnedWithCoefficients(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
        ) !Self {
            for (owned_columns) |column| try column.validate();
            if (owned_coefficients) |coeffs| {
                if (coeffs.len != owned_columns.len) return CommitmentSchemeError.ShapeMismatch;
            }

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
                .coefficients = owned_coefficients,
                .commitment = commitment,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            freeOwnedColumns(allocator, self.columns);
            if (self.coefficients) |coeffs| {
                for (coeffs) |*coeff| coeff.deinit(allocator);
                allocator.free(coeffs);
            }
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
        coefficient_retention_policy: CoefficientRetentionPolicy,
        twiddle_cache: std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, config: PcsConfig) !Self {
            return .{
                .trees = TreeVec(CommitmentTreeProver(H)).initOwned(
                    try allocator.alloc(CommitmentTreeProver(H), 0),
                ),
                .config = config,
                .coefficient_retention_policy = .always,
                .twiddle_cache = std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)).init(allocator),
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.trees.items) |*tree| tree.deinit(allocator);
            self.trees.deinit(allocator);
            deinitTwiddleCache(allocator, &self.twiddle_cache);
            self.* = undefined;
        }

        pub fn setStorePolynomialsCoefficients(self: *Self) void {
            self.coefficient_retention_policy = .always;
        }

        pub fn commit(
            self: *Self,
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
            channel: anytype,
        ) !void {
            var prepared = try prepareColumnsForCommitBorrowed(
                allocator,
                columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_cache,
            );
            errdefer prepared.deinit(allocator);

            var tree = try CommitmentTreeProver(H).initOwnedWithCoefficients(
                allocator,
                prepared.columns,
                prepared.coefficients,
            );
            errdefer tree.deinit(allocator);
            try self.appendCommittedTree(allocator, tree, channel);
        }

        /// Commits owned evaluation columns directly, avoiding an extra column clone.
        ///
        /// Ownership:
        /// - On success, ownership is transferred into the commitment tree.
        /// - On failure, owned columns are fully deinitialized.
        pub fn commitOwned(
            self: *Self,
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            channel: anytype,
        ) !void {
            return self.commitOwnedWithRecorder(allocator, owned_columns, null, channel);
        }

        pub fn commitOwnedWithRecorder(
            self: *Self,
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            errdefer freeOwnedColumnEvaluations(allocator, owned_columns);
            var prepared = try prepareColumnsForCommitOwned(
                allocator,
                owned_columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_cache,
                recorder,
            );
            errdefer prepared.deinit(allocator);

            var merkle_commit_stage = try stage_profile.StageScope.begin(
                recorder,
                "merkle_commit",
                "Merkle commit",
            );
            defer merkle_commit_stage.end();
            var tree = try CommitmentTreeProver(H).initOwnedWithCoefficients(
                allocator,
                prepared.columns,
                prepared.coefficients,
            );
            errdefer tree.deinit(allocator);
            try self.appendCommittedTree(allocator, tree, channel);
        }

        /// Commits coefficient-form circle polynomials directly.
        ///
        /// Inputs:
        /// - `polys`: coefficient polynomials over canonic cosets.
        ///
        /// Semantics:
        /// - evaluates each polynomial on the commitment domain extended by
        ///   `config.fri_config.log_blowup_factor`.
        /// - optionally stores cloned coefficients according to the
        ///   configured retention policy.
        pub fn commitPolys(
            self: *Self,
            allocator: std.mem.Allocator,
            polys: []const prover_circle.CircleCoefficients,
            channel: anytype,
        ) !void {
            const blowup = self.config.fri_config.log_blowup_factor;
            const columns = try extendCoefficientColumnsByGroup(
                allocator,
                polys,
                blowup,
                &self.twiddle_cache,
            );
            errdefer freeOwnedColumnEvaluations(allocator, columns);

            var stored_coefficients: ?[]prover_circle.CircleCoefficients = null;
            if (shouldRetainPolynomialCoefficients(polys, self.coefficient_retention_policy)) {
                const coeffs = try allocator.alloc(prover_circle.CircleCoefficients, polys.len);
                errdefer allocator.free(coeffs);

                var initialized_coeffs: usize = 0;
                errdefer {
                    for (coeffs[0..initialized_coeffs]) |*coeff| coeff.deinit(allocator);
                    allocator.free(coeffs);
                }

                for (polys, 0..) |poly, i| {
                    coeffs[i] = try prover_circle.CircleCoefficients.initOwned(
                        try allocator.dupe(M31, poly.coefficients()),
                    );
                    initialized_coeffs += 1;
                }
                stored_coefficients = coeffs;
            }

            var tree = try CommitmentTreeProver(H).initOwnedWithCoefficients(
                allocator,
                columns,
                stored_coefficients,
            );
            errdefer tree.deinit(allocator);
            try self.appendCommittedTree(allocator, tree, channel);
        }

        pub fn treeBuilder(self: *Self, allocator: std.mem.Allocator) TreeBuilder(H, MC) {
            return .{
                .allocator = allocator,
                .tree_index = self.trees.items.len,
                .commitment_scheme = self,
                .columns = std.ArrayList(ColumnEvaluation).empty,
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
        ) !TreeVec([]const component_prover.Poly) {
            const out = try allocator.alloc([]const component_prover.Poly, self.trees.items.len);
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
            return TreeVec([]const component_prover.Poly).initOwned(out);
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
            return self.proveValuesWithRecorder(allocator, sampled_points, null, channel);
        }

        pub fn proveValuesWithRecorder(
            self: Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !pcs_core.ExtendedCommitmentSchemeProof(H) {
            var scheme = self;
            const lifting_log_size = try scheme.maxTreeLogSize();
            const sampled_values = blk: {
                var sampled_value_eval_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "sampled_value_evaluation",
                    "Sampled-value evaluation",
                );
                defer sampled_value_eval_stage.end();
                break :blk try scheme.evaluateSampledValuesAndRelease(
                    allocator,
                    sampled_points,
                    lifting_log_size,
                );
            };
            return scheme.proveValuesFromSamplesWithRecorder(
                allocator,
                sampled_points,
                sampled_values,
                recorder,
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
            return self.proveValuesFromSamplesWithRecorder(
                allocator,
                sampled_points,
                sampled_values,
                null,
                channel,
            );
        }

        pub fn proveValuesFromSamplesWithRecorder(
            self: Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !pcs_core.ExtendedCommitmentSchemeProof(H) {
            var scheme = self;
            defer scheme.deinit(allocator);
            var sampled_points_owned = sampled_points;
            defer sampled_points_owned.deinitDeep(allocator);
            var sampled_values_owned = sampled_values;
            errdefer sampled_values_owned.deinitDeep(allocator);

            if (scheme.trees.items.len != sampled_points_owned.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }
            if (scheme.trees.items.len != sampled_values_owned.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }

            for (scheme.trees.items, sampled_points_owned.items, sampled_values_owned.items) |tree, tree_points, tree_values| {
                if (tree.columns.len != tree_points.len) return CommitmentSchemeError.ShapeMismatch;
                if (tree.columns.len != tree_values.len) return CommitmentSchemeError.ShapeMismatch;
            }

            {
                var sampled_value_mix_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "sampled_value_channel_mix",
                    "Sampled-value channel mix",
                );
                defer sampled_value_mix_stage.end();
                try mixSampledValuesIntoChannel(allocator, channel, sampled_values_owned);
            }

            const random_coeff = channel.drawSecureFelt();

            const lifting_log_size = try scheme.maxTreeLogSize();
            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

            const borrowed_columns_items = try allocator.alloc([]const ColumnEvaluation, scheme.trees.items.len);
            defer allocator.free(borrowed_columns_items);
            for (scheme.trees.items, 0..) |tree, i| {
                borrowed_columns_items[i] = tree.columns;
            }

            const quotients_column = blk: {
                var fri_quotient_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "fri_quotient_build",
                    "FRI quotient build",
                );
                defer fri_quotient_stage.end();
                break :blk try quotient_ops.computeFriQuotients(
                    allocator,
                    TreeVec([]const ColumnEvaluation).initOwned(borrowed_columns_items),
                    sampled_points_owned,
                    sampled_values_owned,
                    random_coeff,
                    lifting_log_size,
                    scheme.config.fri_config.log_blowup_factor,
                );
            };

            var fri_prover = blk: {
                var fri_commit_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "fri_commit",
                    "FRI commit",
                );
                defer fri_commit_stage.end();
                break :blk try prover_fri.FriProver(H, MC).commit(
                    allocator,
                    channel,
                    scheme.config.fri_config,
                    domain,
                    quotients_column,
                );
            };

            const proof_of_work = blk: {
                var proof_of_work_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "proof_of_work",
                    "Proof of work",
                );
                defer proof_of_work_stage.end();
                const nonce = grind(channel, scheme.config.pow_bits);
                channel.mixU64(nonce);
                break :blk nonce;
            };

            var fri_decommit = blk: {
                var fri_decommit_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "fri_decommit",
                    "FRI decommit",
                );
                defer fri_decommit_stage.end();
                break :blk try fri_prover.decommit(allocator, channel);
            };
            errdefer fri_decommit.deinit(allocator);

            var trace_decommit = blk: {
                var trace_decommit_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "trace_decommit",
                    "Trace decommit",
                );
                defer trace_decommit_stage.end();
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

                break :blk try scheme.decommitByTreePositions(
                    allocator,
                    TreeVec([]const usize).initOwned(query_positions_const),
                );
            };
            errdefer trace_decommit.deinit(allocator);

            var commitments = try scheme.roots(allocator);
            errdefer commitments.deinit(allocator);

            // `query_positions` are only needed for prover-side decommit orchestration.
            allocator.free(fri_decommit.query_positions);
            fri_decommit.query_positions = &[_]usize{};

            return .{
                .proof = .{
                    .config = scheme.config,
                    .commitments = commitments,
                    .sampled_values = sampled_values_owned,
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

        fn evaluateSampledValuesAndRelease(
            self: *Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            lifting_log_size: u32,
        ) !TreeVec([][]QM31) {
            if (self.trees.items.len != sampled_points.items.len) return CommitmentSchemeError.ShapeMismatch;

            var barycentric_cache = std.AutoHashMap(u32, BarycentricContextCacheEntry).init(allocator);
            defer {
                var it = barycentric_cache.valueIterator();
                while (it.next()) |entry| entry.deinit(allocator);
                barycentric_cache.deinit();
            }

            const out = try allocator.alloc([][]QM31, self.trees.items.len);
            errdefer allocator.free(out);

            var initialized_trees: usize = 0;
            errdefer {
                for (out[0..initialized_trees]) |tree_values| {
                    for (tree_values) |column_values| allocator.free(column_values);
                    allocator.free(tree_values);
                }
            }

            for (self.trees.items, sampled_points.items, 0..) |*tree, tree_points, tree_idx| {
                if (tree.columns.len != tree_points.len) return CommitmentSchemeError.ShapeMismatch;
                if (tree.coefficients) |coeffs| {
                    if (coeffs.len != tree.columns.len) return CommitmentSchemeError.ShapeMismatch;
                }

                var coefficient_plans = std.ArrayList(CoefficientEvalPlan).empty;
                defer deinitCoefficientEvalPlans(allocator, &coefficient_plans);
                var coefficient_plan_index = std.AutoHashMap(u64, usize).init(allocator);
                defer coefficient_plan_index.deinit();

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

                    const values = try allocator.alloc(QM31, points.len);
                    tree_values[col_idx] = values;
                    initialized_columns += 1;

                    const fold_count = lifting_log_size - column.log_size;
                    if (tree.coefficients) |coeffs| {
                        const coeff = coeffs[col_idx];
                        const plan = try getOrCreateCoefficientEvalPlan(
                            allocator,
                            &coefficient_plan_index,
                            &coefficient_plans,
                            coeff.logSize(),
                            fold_count,
                            points,
                        );
                        try plan.column_indices.append(allocator, col_idx);
                    } else {
                        const evaluation = try prover_circle.CircleEvaluation.init(
                            canonic.CanonicCoset.new(column.log_size).circleDomain(),
                            column.values,
                        );
                        const cache_entry = try getBarycentricCacheEntry(
                            allocator,
                            &barycentric_cache,
                            column.log_size,
                        );
                        for (points, 0..) |point, i| {
                            const folded_point = point.repeatedDouble(fold_count);
                            values[i] = try evaluation.barycentricEvalAtPointWithContext(
                                allocator,
                                &cache_entry.context,
                                &cache_entry.workspace,
                                folded_point,
                            );
                        }
                    }
                }

                if (tree.coefficients) |coeffs| {
                    try evaluateCoefficientPlans(
                        allocator,
                        coeffs,
                        tree_values,
                        coefficient_plans.items,
                    );
                    for (coeffs) |*coeff| coeff.deinit(allocator);
                    allocator.free(coeffs);
                    tree.coefficients = null;
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
            self.columns.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn extendColumns(self: *Self, cols: []const ColumnEvaluation) !TreeSubspan {
            const col_start = self.columns.items.len;
            for (cols) |column| {
                try column.validate();
                try self.columns.append(self.allocator, .{
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
            const base_columns = try self.columns.toOwnedSlice(self.allocator);
            self.columns = std.ArrayList(ColumnEvaluation).empty;
            errdefer {
                freeOwnedColumnEvaluations(self.allocator, base_columns);
            }

            var prepared = try prepareColumnsForCommitOwned(
                self.allocator,
                base_columns,
                self.commitment_scheme.config.fri_config.log_blowup_factor,
                self.commitment_scheme.coefficient_retention_policy,
                &self.commitment_scheme.twiddle_cache,
                null,
            );
            errdefer prepared.deinit(self.allocator);

            var tree = try CommitmentTreeProver(H).initOwnedWithCoefficients(
                self.allocator,
                prepared.columns,
                prepared.coefficients,
            );
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

fn mixSampledValuesIntoChannel(
    allocator: std.mem.Allocator,
    channel: anytype,
    sampled_values: TreeVec([][]QM31),
) !void {
    const Channel = @TypeOf(channel.*);
    if (@hasField(Channel, "channel")) {
        try mixSampledValuesIntoChannel(allocator, &channel.channel, sampled_values);
        return;
    }

    if (Channel == channel_blake2s.Blake2sChannel) {
        mixSampledValuesIntoBlake2Channel(false, channel, sampled_values);
        return;
    }
    if (Channel == channel_blake2s.Blake2sM31Channel) {
        mixSampledValuesIntoBlake2Channel(true, channel, sampled_values);
        return;
    }

    const flat = try flattenSampledValues(allocator, sampled_values);
    defer allocator.free(flat);
    channel.mixFelts(flat);
}

fn mixSampledValuesIntoBlake2Channel(
    comptime is_m31_output: bool,
    channel: *channel_blake2s.Blake2sChannelGeneric(is_m31_output),
    sampled_values: TreeVec([][]QM31),
) void {
    var hasher = blake2_hash.Blake2sHasherGeneric(is_m31_output).init();
    const digest = channel.digestBytes();
    hasher.update(digest[0..]);

    if (builtin.cpu.arch.endian() == .little) {
        for (sampled_values.items) |tree_values| {
            for (tree_values) |column_values| {
                if (column_values.len == 0) continue;
                hasher.update(std.mem.sliceAsBytes(column_values));
            }
        }
    } else {
        var scratch: [256 * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31)]u8 = undefined;
        for (sampled_values.items) |tree_values| {
            for (tree_values) |column_values| {
                var at: usize = 0;
                while (at < column_values.len) {
                    const chunk_len = @min(@as(usize, 256), column_values.len - at);
                    packSecureFeltsLe(
                        scratch[0 .. chunk_len * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31)],
                        column_values[at .. at + chunk_len],
                    );
                    hasher.update(scratch[0 .. chunk_len * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31)]);
                    at += chunk_len;
                }
            }
        }
    }

    channel.updateDigest(hasher.finalize());
}

fn packSecureFeltsLe(dst: []u8, values: []const QM31) void {
    std.debug.assert(dst.len == values.len * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31));
    var at: usize = 0;
    for (values) |value| {
        const coords = value.toM31Array();
        inline for (coords) |coord| {
            const encoded = coord.toBytesLe();
            @memcpy(dst[at .. at + @sizeOf(M31)], encoded[0..]);
            at += @sizeOf(M31);
        }
    }
}

test "prover pcs: streaming sampled-value mixing matches flattening path" {
    const alloc = std.testing.allocator;
    const LoggingChannel = @import("../channel/logging_channel.zig").LoggingChannel;

    const col00 = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    });
    defer alloc.free(col00);
    const col01 = try alloc.alloc(QM31, 0);
    defer alloc.free(col01);
    const col10 = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(9, 10, 11, 12),
    });
    defer alloc.free(col10);
    const col11 = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
    });
    defer alloc.free(col11);

    const tree0 = try alloc.dupe([]QM31, &[_][]QM31{ col00, col01 });
    defer alloc.free(tree0);
    const tree1 = try alloc.dupe([]QM31, &[_][]QM31{ col10, col11 });
    defer alloc.free(tree1);

    var sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{ tree0, tree1 }),
    );
    defer sampled_values.deinitDeep(alloc);

    const flat = try flattenSampledValues(alloc, sampled_values);
    defer alloc.free(flat);

    var expected_blake2 = channel_blake2s.Blake2sChannel{};
    expected_blake2.mixFelts(flat);
    var actual_blake2 = channel_blake2s.Blake2sChannel{};
    try mixSampledValuesIntoChannel(alloc, &actual_blake2, sampled_values);
    try std.testing.expectEqualSlices(u8, expected_blake2.digestBytes()[0..], actual_blake2.digestBytes()[0..]);

    var expected_blake2_m31 = channel_blake2s.Blake2sM31Channel{};
    expected_blake2_m31.mixFelts(flat);
    var actual_blake2_m31 = channel_blake2s.Blake2sM31Channel{};
    try mixSampledValuesIntoChannel(alloc, &actual_blake2_m31, sampled_values);
    try std.testing.expectEqualSlices(u8, expected_blake2_m31.digestBytes()[0..], actual_blake2_m31.digestBytes()[0..]);

    var expected_logging = LoggingChannel(channel_blake2s.Blake2sChannel).init(.{});
    expected_logging.mixFelts(flat);
    var actual_logging = LoggingChannel(channel_blake2s.Blake2sChannel).init(.{});
    try mixSampledValuesIntoChannel(alloc, &actual_logging, sampled_values);
    try std.testing.expectEqualSlices(
        u8,
        expected_logging.channel.digestBytes()[0..],
        actual_logging.channel.digestBytes()[0..],
    );
}

test "prover pcs: coefficient eval plan cache reuses duplicate point sets" {
    const alloc = std.testing.allocator;

    const points_a = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(23),
    });
    defer alloc.free(points_a);
    const points_b = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(23),
    });
    defer alloc.free(points_b);
    const points_c = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    });
    defer alloc.free(points_c);

    var plans = std.ArrayList(CoefficientEvalPlan).empty;
    defer deinitCoefficientEvalPlans(alloc, &plans);
    var index = std.AutoHashMap(u64, usize).init(alloc);
    defer index.deinit();

    const plan_a = try getOrCreateCoefficientEvalPlan(
        alloc,
        &index,
        &plans,
        6,
        1,
        points_a,
    );
    try plan_a.column_indices.append(alloc, 0);

    _ = try getOrCreateCoefficientEvalPlan(
        alloc,
        &index,
        &plans,
        6,
        1,
        points_b,
    );
    try std.testing.expectEqual(@as(usize, 1), plans.items.len);

    _ = try getOrCreateCoefficientEvalPlan(
        alloc,
        &index,
        &plans,
        6,
        1,
        points_c,
    );
    try std.testing.expectEqual(@as(usize, 2), plans.items.len);
}

const PreparedCommitmentColumns = struct {
    columns: []ColumnEvaluation,
    coefficients: ?[]prover_circle.CircleCoefficients,

    fn deinit(self: *PreparedCommitmentColumns, allocator: std.mem.Allocator) void {
        freeOwnedColumnEvaluations(allocator, self.columns);
        if (self.coefficients) |coeffs| {
            deinitOwnedCoefficientColumns(allocator, coeffs);
        }
        self.* = undefined;
    }
};

fn prepareColumnsForCommitBorrowed(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) !PreparedCommitmentColumns {
    const owned = try allocator.alloc(ColumnEvaluation, columns.len);
    errdefer allocator.free(owned);

    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |column| allocator.free(column.values);
    }

    for (columns, 0..) |column, i| {
        try column.validate();
        owned[i] = .{
            .log_size = column.log_size,
            .values = try allocator.dupe(M31, column.values),
        };
        initialized += 1;
    }

    return prepareColumnsForCommitOwned(
        allocator,
        owned,
        log_blowup_factor,
        retention_policy,
        twiddle_cache,
        null,
    );
}

fn prepareColumnsForCommitOwned(
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
    recorder: ?*stage_profile.Recorder,
) !PreparedCommitmentColumns {
    const retain_coefficients = shouldRetainCoefficients(owned_columns, retention_policy);
    if (log_blowup_factor == 0 and !retain_coefficients) {
        return .{
            .columns = owned_columns,
            .coefficients = null,
        };
    }

    if (log_blowup_factor == 0) {
        {
            var interpolate_stage = try stage_profile.StageScope.begin(
                recorder,
                "interpolate_columns",
                "Interpolate columns",
            );
            defer interpolate_stage.end();
            const coeffs = try interpolateCoefficientColumns(allocator, owned_columns, twiddle_cache);
            return .{
                .columns = owned_columns,
                .coefficients = coeffs,
            };
        }
    }

    const coeffs = blk: {
        var interpolate_stage = try stage_profile.StageScope.begin(
            recorder,
            "interpolate_columns",
            "Interpolate columns",
        );
        defer interpolate_stage.end();
        break :blk try interpolateOwnedColumnsForExtension(allocator, owned_columns, twiddle_cache);
    };
    errdefer deinitOwnedCoefficientColumns(allocator, coeffs);
    allocator.free(owned_columns);

    const extended = blk: {
        var eval_stage = try stage_profile.StageScope.begin(
            recorder,
            "evaluate_extended_domain",
            "Evaluate extended domain",
        );
        defer eval_stage.end();
        break :blk try extendCoefficientColumnsByGroup(
            allocator,
            coeffs,
            log_blowup_factor,
            twiddle_cache,
        );
    };

    if (!retain_coefficients) {
        deinitOwnedCoefficientColumns(allocator, coeffs);
        return .{
            .columns = extended,
            .coefficients = null,
        };
    }

    return .{
        .columns = extended,
        .coefficients = coeffs,
    };
}

fn shouldRetainCoefficients(
    columns: []const ColumnEvaluation,
    retention_policy: CoefficientRetentionPolicy,
) bool {
    return switch (retention_policy) {
        .always => true,
        .never => false,
        .auto => blk: {
            var total_bytes: usize = 0;
            for (columns) |column| {
                const column_bytes = std.math.mul(usize, column.values.len, @sizeOf(M31)) catch break :blk false;
                total_bytes = std.math.add(usize, total_bytes, column_bytes) catch break :blk false;
                if (total_bytes > COEFFICIENT_STORAGE_AUTO_MAX_BYTES) break :blk false;
            }
            break :blk true;
        },
    };
}

fn shouldRetainPolynomialCoefficients(
    polys: []const prover_circle.CircleCoefficients,
    retention_policy: CoefficientRetentionPolicy,
) bool {
    return switch (retention_policy) {
        .always => true,
        .never => false,
        .auto => blk: {
            var total_bytes: usize = 0;
            for (polys) |poly| {
                const poly_bytes = std.math.mul(usize, poly.coefficients().len, @sizeOf(M31)) catch break :blk false;
                total_bytes = std.math.add(usize, total_bytes, poly_bytes) catch break :blk false;
                if (total_bytes > COEFFICIENT_STORAGE_AUTO_MAX_BYTES) break :blk false;
            }
            break :blk true;
        },
    };
}

fn interpolateCoefficientColumns(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) ![]prover_circle.CircleCoefficients {
    const out = try allocator.alloc(prover_circle.CircleCoefficients, columns.len);
    errdefer allocator.free(out);

    var initialized_indices = std.ArrayList(usize).empty;
    defer initialized_indices.deinit(allocator);
    errdefer {
        for (initialized_indices.items) |idx| out[idx].deinit(allocator);
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromColumns(allocator, columns);
    defer deinitLogSizeGroups(allocator, &groups);

    for (groups.items) |group| {
        const twiddle_tree = try getCachedTwiddleTree(allocator, twiddle_cache, group.log_size);
        const domain = canonic.CanonicCoset.new(group.log_size).circleDomain();
        const batch_len = preferredFftBatchLen(domain.size());
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);
            if (chunk_len == 1) {
                const idx = group.indices.items[batch_start];
                out[idx] = try interpolateSingleCoefficientColumn(allocator, columns[idx], twiddle_cache);
                try initialized_indices.append(allocator, idx);
                continue;
            }

            const batch_values = try allocator.alloc([]M31, chunk_len);
            defer allocator.free(batch_values);

            var initialized_batch: usize = 0;
            errdefer {
                for (batch_values[0..initialized_batch]) |values| allocator.free(values);
            }

            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                batch_values[batch_idx] = try allocator.dupe(M31, columns[idx].values);
                initialized_batch += 1;
            }

            try prover_circle.poly.interpolateOwnedValuesBatchWithTwiddles(
                domain,
                batch_values,
                twiddleTreeConst(twiddle_tree),
            );
            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                out[idx] = try prover_circle.CircleCoefficients.initOwned(batch_values[batch_idx]);
                try initialized_indices.append(allocator, idx);
            }
        }
    }
    return out;
}

fn interpolateOwnedColumnsForExtension(
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) ![]prover_circle.CircleCoefficients {
    const out = try allocator.alloc(prover_circle.CircleCoefficients, owned_columns.len);
    errdefer allocator.free(out);

    var initialized_indices = std.ArrayList(usize).empty;
    defer initialized_indices.deinit(allocator);
    errdefer {
        for (initialized_indices.items) |idx| out[idx].deinit(allocator);
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromColumns(allocator, owned_columns);
    defer deinitLogSizeGroups(allocator, &groups);

    for (groups.items) |group| {
        const twiddle_tree = try getCachedTwiddleTree(allocator, twiddle_cache, group.log_size);
        const domain = canonic.CanonicCoset.new(group.log_size).circleDomain();
        const batch_len = preferredFftBatchLen(domain.size());
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);
            if (chunk_len == 1) {
                const idx = group.indices.items[batch_start];
                out[idx] = try interpolateOwnedSingleCoefficientColumn(
                    allocator,
                    owned_columns[idx],
                    twiddle_cache,
                );
                owned_columns[idx].values = &[_]M31{};
                try initialized_indices.append(allocator, idx);
                continue;
            }

            const batch_values = try allocator.alloc([]M31, chunk_len);
            defer allocator.free(batch_values);

            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                batch_values[batch_idx] = @constCast(owned_columns[idx].values);
            }

            try prover_circle.poly.interpolateOwnedValuesBatchWithTwiddles(
                domain,
                batch_values,
                twiddleTreeConst(twiddle_tree),
            );
            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                out[idx] = try prover_circle.CircleCoefficients.initOwned(batch_values[batch_idx]);
                owned_columns[idx].values = &[_]M31{};
                try initialized_indices.append(allocator, idx);
            }
        }
    }

    return out;
}

fn extendCoefficientColumnsByGroup(
    allocator: std.mem.Allocator,
    coeffs: []const prover_circle.CircleCoefficients,
    log_blowup_factor: u32,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) ![]ColumnEvaluation {
    const out = try allocator.alloc(ColumnEvaluation, coeffs.len);
    errdefer allocator.free(out);
    for (out) |*column| {
        column.* = .{
            .log_size = 0,
            .values = &[_]M31{},
        };
    }
    errdefer {
        for (out) |column| {
            if (column.values.len != 0) allocator.free(column.values);
        }
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromCoefficients(allocator, coeffs);
    defer deinitLogSizeGroups(allocator, &groups);

    for (groups.items) |group| {
        const extended_log_size = std.math.add(u32, group.log_size, log_blowup_factor) catch
            return CommitmentSchemeError.ShapeMismatch;
        const twiddle_tree = try getCachedTwiddleTree(allocator, twiddle_cache, extended_log_size);
        const domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();

        const batch_len = preferredFftBatchLen(domain.size());
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);
            if (chunk_len == 1) {
                const idx = group.indices.items[batch_start];
                const evaluation = try coeffs[idx].evaluateWithTwiddles(
                    allocator,
                    domain,
                    twiddleTreeConst(twiddle_tree),
                );
                out[idx] = .{
                    .log_size = extended_log_size,
                    .values = evaluation.values,
                };
                continue;
            }

            const batch_polys = try allocator.alloc(prover_circle.CircleCoefficients, chunk_len);
            defer allocator.free(batch_polys);
            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                batch_polys[batch_idx] = coeffs[idx];
            }

            const batch_values = try prover_circle.poly.evaluateManyWithTwiddles(
                allocator,
                batch_polys,
                domain,
                twiddleTreeConst(twiddle_tree),
            );
            defer allocator.free(batch_values);

            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                out[idx] = .{
                    .log_size = extended_log_size,
                    .values = batch_values[batch_idx],
                };
            }
        }
    }

    return out;
}

fn interpolateSingleCoefficientColumn(
    allocator: std.mem.Allocator,
    column: ColumnEvaluation,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) !prover_circle.CircleCoefficients {
    const domain = canonic.CanonicCoset.new(column.log_size).circleDomain();
    const twiddle_tree = try getCachedTwiddleTree(allocator, twiddle_cache, column.log_size);
    const evaluation = try prover_circle.CircleEvaluation.init(domain, column.values);
    return prover_circle.poly.interpolateFromEvaluationWithTwiddles(
        allocator,
        evaluation,
        twiddleTreeConst(twiddle_tree),
    );
}

fn interpolateOwnedSingleCoefficientColumn(
    allocator: std.mem.Allocator,
    column: ColumnEvaluation,
    twiddle_cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) !prover_circle.CircleCoefficients {
    const domain = canonic.CanonicCoset.new(column.log_size).circleDomain();
    const twiddle_tree = try getCachedTwiddleTree(allocator, twiddle_cache, column.log_size);
    return prover_circle.poly.interpolateOwnedValuesWithTwiddles(
        domain,
        @constCast(column.values),
        twiddleTreeConst(twiddle_tree),
    );
}

fn deinitOwnedCoefficientColumns(
    allocator: std.mem.Allocator,
    columns: []prover_circle.CircleCoefficients,
) void {
    for (columns) |*coeff| coeff.deinit(allocator);
    allocator.free(columns);
}

const LogSizeGroup = struct {
    log_size: u32,
    indices: std.ArrayList(usize),

    fn deinit(self: *LogSizeGroup, allocator: std.mem.Allocator) void {
        self.indices.deinit(allocator);
        self.* = undefined;
    }
};

fn buildLogSizeGroupsFromColumns(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
) !std.ArrayList(LogSizeGroup) {
    var groups = std.ArrayList(LogSizeGroup).empty;
    errdefer deinitLogSizeGroups(allocator, &groups);

    for (columns, 0..) |column, idx| {
        try appendLogSizeGroupIndex(allocator, &groups, column.log_size, idx);
    }
    return groups;
}

fn buildLogSizeGroupsFromCoefficients(
    allocator: std.mem.Allocator,
    coeffs: []const prover_circle.CircleCoefficients,
) !std.ArrayList(LogSizeGroup) {
    var groups = std.ArrayList(LogSizeGroup).empty;
    errdefer deinitLogSizeGroups(allocator, &groups);

    for (coeffs, 0..) |coeff, idx| {
        try appendLogSizeGroupIndex(allocator, &groups, coeff.logSize(), idx);
    }
    return groups;
}

fn appendLogSizeGroupIndex(
    allocator: std.mem.Allocator,
    groups: *std.ArrayList(LogSizeGroup),
    log_size: u32,
    idx: usize,
) !void {
    for (groups.items, 0..) |group, group_idx| {
        if (group.log_size == log_size) {
            try groups.items[group_idx].indices.append(allocator, idx);
            return;
        }
    }

    try groups.append(allocator, .{
        .log_size = log_size,
        .indices = std.ArrayList(usize).empty,
    });
    try groups.items[groups.items.len - 1].indices.append(allocator, idx);
}

fn deinitLogSizeGroups(
    allocator: std.mem.Allocator,
    groups: *std.ArrayList(LogSizeGroup),
) void {
    for (groups.items) |*group| group.deinit(allocator);
    groups.deinit(allocator);
}

fn twiddleTreeConst(tree: twiddles_mod.TwiddleTree([]M31)) twiddles_mod.TwiddleTree([]const M31) {
    return .{
        .root_coset = tree.root_coset,
        .twiddles = tree.twiddles,
        .itwiddles = tree.itwiddles,
    };
}

fn getCachedTwiddleTree(
    allocator: std.mem.Allocator,
    cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
    log_size: u32,
) !twiddles_mod.TwiddleTree([]M31) {
    const gop = try cache.getOrPut(log_size);
    if (!gop.found_existing) {
        gop.value_ptr.* = try twiddles_mod.precomputeM31(
            allocator,
            canonic.CanonicCoset.new(log_size).circleDomain().half_coset,
        );
    }
    return gop.value_ptr.*;
}

fn deinitTwiddleCache(
    allocator: std.mem.Allocator,
    cache: *std.AutoHashMap(u32, twiddles_mod.TwiddleTree([]M31)),
) void {
    var it = cache.valueIterator();
    while (it.next()) |tree| twiddles_mod.deinitM31(allocator, tree);
    cache.deinit();
}

const BarycentricContextCacheEntry = struct {
    context: prover_circle_eval.BarycentricContext,
    workspace: prover_circle_eval.BarycentricWorkspace,

    fn deinit(self: *BarycentricContextCacheEntry, allocator: std.mem.Allocator) void {
        self.context.deinit(allocator);
        self.workspace.deinit(allocator);
        self.* = undefined;
    }
};

const CoefficientEvalPlan = struct {
    coeff_log_size: u32,
    fold_count: u32,
    normalized_points: []CirclePointQM31,
    flat_factors: []QM31,
    column_indices: std.ArrayList(usize),
    next_same_hash: ?usize,

    fn deinit(self: *CoefficientEvalPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.normalized_points);
        allocator.free(self.flat_factors);
        self.column_indices.deinit(allocator);
        self.* = undefined;
    }
};

fn deinitCoefficientEvalPlans(
    allocator: std.mem.Allocator,
    plans: *std.ArrayList(CoefficientEvalPlan),
) void {
    for (plans.items) |*plan| plan.deinit(allocator);
    plans.deinit(allocator);
}

fn getOrCreateCoefficientEvalPlan(
    allocator: std.mem.Allocator,
    index: *std.AutoHashMap(u64, usize),
    plans: *std.ArrayList(CoefficientEvalPlan),
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
) !*CoefficientEvalPlan {
    const plan_hash = hashCoefficientEvalPlanKey(
        coeff_log_size,
        fold_count,
        points,
    );
    var existing_plan_idx = index.get(plan_hash);
    while (existing_plan_idx) |plan_idx| {
        const plan = &plans.items[plan_idx];
        if (plan.coeff_log_size == coeff_log_size and
            plan.fold_count == fold_count and
            coefficientEvalPlanMatchesPoints(plan.*, points))
        {
            return plan;
        }
        existing_plan_idx = plan.next_same_hash;
    }

    const normalized = try buildCoefficientEvalPlanData(
        allocator,
        coeff_log_size,
        fold_count,
        points,
    );
    errdefer allocator.free(normalized.normalized_points);
    errdefer allocator.free(normalized.flat_factors);

    try plans.append(allocator, .{
        .coeff_log_size = coeff_log_size,
        .fold_count = fold_count,
        .normalized_points = normalized.normalized_points,
        .flat_factors = normalized.flat_factors,
        .column_indices = std.ArrayList(usize).empty,
        .next_same_hash = index.get(plan_hash),
    });
    errdefer {
        var plan = plans.items[plans.items.len - 1];
        plans.items.len -= 1;
        plan.deinit(allocator);
    }
    try index.put(plan_hash, plans.items.len - 1);
    return &plans.items[plans.items.len - 1];
}

const CoefficientEvalPlanData = struct {
    normalized_points: []CirclePointQM31,
    flat_factors: []QM31,
};

const COEFFICIENT_PLAN_KEY_POINT_BYTES: usize = 2 * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);

fn hashCoefficientEvalPlanKey(
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
) u64 {
    var hasher = std.hash.Wyhash.init(0);
    var header: [3 * @sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], coeff_log_size, .little);
    std.mem.writeInt(u32, header[4..8], fold_count, .little);
    std.mem.writeInt(u32, header[8..12], @intCast(points.len), .little);
    hasher.update(header[0..]);

    var point_bytes: [COEFFICIENT_PLAN_KEY_POINT_BYTES]u8 = undefined;
    for (points) |point| {
        packPointKeyBytes(
            point_bytes[0..],
            if (fold_count == 0) point else point.repeatedDouble(fold_count),
        );
        hasher.update(point_bytes[0..]);
    }
    return hasher.final();
}

fn buildCoefficientEvalPlanData(
    allocator: std.mem.Allocator,
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
) !CoefficientEvalPlanData {
    const normalized_points = try allocator.alloc(CirclePointQM31, points.len);
    errdefer allocator.free(normalized_points);

    const flat_factors = try allocator.alloc(QM31, points.len * coeff_log_size);
    errdefer allocator.free(flat_factors);

    var factor_buffer: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
    var factor_at: usize = 0;
    for (points, 0..) |point, point_idx| {
        const folded_point = if (fold_count == 0) point else point.repeatedDouble(fold_count);
        normalized_points[point_idx] = folded_point;

        if (coeff_log_size == 0) continue;
        const factors = prover_circle.poly.fillEvalFactorsForPoint(
            folded_point,
            coeff_log_size,
            &factor_buffer,
        );
        @memcpy(flat_factors[factor_at .. factor_at + coeff_log_size], factors);
        factor_at += coeff_log_size;
    }

    return .{
        .normalized_points = normalized_points,
        .flat_factors = flat_factors,
    };
}

fn coefficientEvalPlanMatchesPoints(
    plan: CoefficientEvalPlan,
    points: []const CirclePointQM31,
) bool {
    if (plan.normalized_points.len != points.len) return false;
    for (points, plan.normalized_points) |point, normalized_point| {
        const folded_point = if (plan.fold_count == 0) point else point.repeatedDouble(plan.fold_count);
        if (!folded_point.eql(normalized_point)) return false;
    }
    return true;
}

fn packPointKeyBytes(dst: []u8, point: CirclePointQM31) void {
    std.debug.assert(dst.len == COEFFICIENT_PLAN_KEY_POINT_BYTES);
    var at: usize = 0;
    inline for (.{ point.x, point.y }) |coord| {
        const coords = coord.toM31Array();
        inline for (coords) |mcoord| {
            const encoded = mcoord.toBytesLe();
            @memcpy(dst[at .. at + @sizeOf(M31)], encoded[0..]);
            at += @sizeOf(M31);
        }
    }
}

fn evaluateCoefficientPlans(
    allocator: std.mem.Allocator,
    coeffs: []const prover_circle.CircleCoefficients,
    tree_values: [][]QM31,
    plans: []const CoefficientEvalPlan,
) !void {
    var batch_coeffs: []prover_circle.CircleCoefficients = &[_]prover_circle.CircleCoefficients{};
    defer if (batch_coeffs.len != 0) allocator.free(batch_coeffs);
    var batch_out: [][]QM31 = &[_][]QM31{};
    defer if (batch_out.len != 0) allocator.free(batch_out);

    for (plans) |plan| {
        if (plan.column_indices.items.len == 0) continue;
        if (plan.column_indices.items.len == 1) {
            const column_idx = plan.column_indices.items[0];
            coeffs[column_idx].evalAtPointsWithFlatFactors(
                plan.flat_factors,
                tree_values[column_idx],
            );
            continue;
        }

        const batch_len = plan.column_indices.items.len;
        if (batch_coeffs.len < batch_len) {
            if (batch_coeffs.len != 0) allocator.free(batch_coeffs);
            if (batch_out.len != 0) allocator.free(batch_out);
            batch_coeffs = try allocator.alloc(prover_circle.CircleCoefficients, batch_len);
            batch_out = try allocator.alloc([]QM31, batch_len);
        }
        const batch_coeffs_view = batch_coeffs[0..batch_len];
        const batch_out_view = batch_out[0..batch_len];

        for (plan.column_indices.items, 0..) |column_idx, batch_idx| {
            batch_coeffs_view[batch_idx] = coeffs[column_idx];
            batch_out_view[batch_idx] = tree_values[column_idx];
        }

        prover_circle.poly.CircleCoefficients.evalManyAtPointsWithFlatFactors(
            batch_coeffs_view,
            plan.flat_factors,
            batch_out_view,
        );
    }
}

fn getBarycentricCacheEntry(
    allocator: std.mem.Allocator,
    cache: *std.AutoHashMap(u32, BarycentricContextCacheEntry),
    log_size: u32,
) !*BarycentricContextCacheEntry {
    const gop = try cache.getOrPut(log_size);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .context = try prover_circle_eval.BarycentricContext.init(allocator, log_size),
            .workspace = prover_circle_eval.BarycentricWorkspace.init(),
        };
    }
    return gop.value_ptr;
}

fn freeOwnedColumnEvaluations(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
) void {
    for (columns) |column| {
        if (column.values.len != 0) allocator.free(column.values);
    }
    allocator.free(columns);
}

fn preferredFftBatchLen(value_len: usize) usize {
    const value_bytes = std.math.mul(usize, value_len, @sizeOf(M31)) catch return 1;
    if (value_bytes == 0) return 1;
    const max_batch = FFT_BATCH_TARGET_BYTES / value_bytes;
    return std.math.clamp(max_batch, 1, 32);
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
    const extended_log_size = @as(u32, 2) + scheme.config.fri_config.log_blowup_factor;
    const expected_sizes = [_]u32{extended_log_size};
    try std.testing.expectEqual(@as(usize, 2), sizes.items.len);
    try std.testing.expectEqualSlices(u32, expected_sizes[0..], sizes.items[0]);
    try std.testing.expectEqualSlices(u32, expected_sizes[0..], sizes.items[1]);
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
    const expected_column = scheme.trees.items[0].columns[0];
    try std.testing.expectEqual(@as(usize, 1), polys.items.len);
    try std.testing.expectEqual(@as(usize, 1), polys.items[0].len);
    try std.testing.expectEqual(expected_column.log_size, polys.items[0][0].log_size);
    try std.testing.expectEqualSlices(M31, expected_column.values, polys.items[0][0].values);

    var trace = try scheme.trace(alloc);
    defer trace.polys.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), trace.polys.items.len);
    try std.testing.expectEqualSlices(M31, expected_column.values, trace.polys.items[0][0].values);
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

test "prover pcs: commit polys applies blowup and stores coefficients" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    defer scheme.deinit(alloc);
    scheme.setStorePolynomialsCoefficients();

    const coeffs = [_]M31{
        M31.fromCanonical(7),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
    };
    const poly = try prover_circle.CircleCoefficients.initBorrowed(coeffs[0..]);

    var channel = Channel{};
    try scheme.commitPolys(alloc, &[_]prover_circle.CircleCoefficients{poly}, &channel);

    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items.len);
    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items[0].columns.len);
    try std.testing.expectEqual(@as(u32, 5), scheme.trees.items[0].columns[0].log_size);
    try std.testing.expectEqual(@as(usize, 32), scheme.trees.items[0].columns[0].values.len);
    try std.testing.expect(scheme.trees.items[0].coefficients != null);
    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items[0].coefficients.?.len);
}

test "prover pcs: commit polys supports mixed log sizes with twiddle cache" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 1, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    defer scheme.deinit(alloc);

    const coeffs_log2 = [_]M31{
        M31.fromCanonical(3),
        M31.zero(),
        M31.zero(),
        M31.zero(),
    };
    const coeffs_log3 = [_]M31{
        M31.fromCanonical(11),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
        M31.zero(),
    };
    const poly0 = try prover_circle.CircleCoefficients.initBorrowed(coeffs_log2[0..]);
    const poly1 = try prover_circle.CircleCoefficients.initBorrowed(coeffs_log3[0..]);

    var channel = Channel{};
    try scheme.commitPolys(
        alloc,
        &[_]prover_circle.CircleCoefficients{ poly0, poly1 },
        &channel,
    );

    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items.len);
    try std.testing.expectEqual(@as(usize, 2), scheme.trees.items[0].columns.len);
    try std.testing.expectEqual(@as(u32, 3), scheme.trees.items[0].columns[0].log_size);
    try std.testing.expectEqual(@as(u32, 4), scheme.trees.items[0].columns[1].log_size);
    try std.testing.expectEqual(@as(usize, 8), scheme.trees.items[0].columns[0].values.len);
    try std.testing.expectEqual(@as(usize, 16), scheme.trees.items[0].columns[1].values.len);
    for (scheme.trees.items[0].columns[0].values) |value| {
        try std.testing.expect(value.eql(M31.fromCanonical(3)));
    }
    for (scheme.trees.items[0].columns[1].values) |value| {
        try std.testing.expect(value.eql(M31.fromCanonical(11)));
    }
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
    const lifting_log_size = @as(u32, 3) + scheme.config.fri_config.log_blowup_factor;
    const pp_max_log_size = @as(u32, 2) + scheme.config.fri_config.log_blowup_factor;
    var tree_queries = try scheme.buildQueryPositionsTree(alloc, query_positions[0..], lifting_log_size);
    defer tree_queries.deinitDeep(alloc);

    const expected_pp = try pcs_utils.preparePreprocessedQueryPositions(
        alloc,
        query_positions[0..],
        lifting_log_size,
        pp_max_log_size,
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

test "prover pcs: stored coefficients fast path computes sampled values" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);
    scheme.setStorePolynomialsCoefficients();

    const column_values = [_]M31{
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const coeffs = scheme.trees.items[0].coefficients orelse return CommitmentSchemeError.ShapeMismatch;
    try std.testing.expectEqual(@as(usize, 1), coeffs.len);
    try std.testing.expectEqual(@as(u32, 3), coeffs[0].logSize());

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(59);
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

test "prover pcs: prove values handles repeated sampled points across columns" {
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

    const col0 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
    };
    const col1 = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 3, .values = col1[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(97);
    const sampled_points_col0_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_prover,
        sampled_points_col1_prover,
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
    try std.testing.expectEqual(@as(usize, 2), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][1].len);
    for (extended_proof.proof.sampled_values.items[0][0]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(9))));
    }
    for (extended_proof.proof.sampled_values.items[0][1]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(13))));
    }

    const sampled_points_col0_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_verify,
        sampled_points_col1_verify,
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
        &[_]u32{ 3, 3 },
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values handles repeated sampled points across mixed log sizes" {
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

    const col0 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
    };
    const col1 = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 2, .values = col1[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(131);
    const sampled_points_col0_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_prover,
        sampled_points_col1_prover,
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
    try std.testing.expectEqual(@as(usize, 2), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][1].len);
    for (extended_proof.proof.sampled_values.items[0][0]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(9))));
    }
    for (extended_proof.proof.sampled_values.items[0][1]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(13))));
    }

    const sampled_points_col0_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_verify,
        sampled_points_col1_verify,
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
        &[_]u32{ 3, 2 },
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

test "prover pcs: prove values paths support non-zero blowup" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme_samples = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 2),
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
    try std.testing.expectEqual(@as(u32, 4), scheme_samples.trees.items[0].columns[0].log_size);
    try std.testing.expectEqual(@as(usize, 16), scheme_samples.trees.items[0].columns[0].values.len);

    const sample_point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(31);
    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col});
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );
    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{QM31.fromBase(M31.fromCanonical(5))});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var proof_samples = try scheme_samples.proveValuesFromSamples(
        alloc,
        sampled_points,
        sampled_values,
        &channel,
    );
    defer proof_samples.aux.deinit(alloc);

    var verifier_samples = try Verifier.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 2),
    });
    defer verifier_samples.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier_samples.commit(
        alloc,
        proof_samples.proof.commitments.items[0],
        &[_]u32{2},
        &verifier_channel,
    );
    try verifier_samples.verifyValues(
        alloc,
        sampled_points_verify,
        proof_samples.proof,
        &verifier_channel,
    );

    var scheme_points = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 2),
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
    const sampled_points_col_only_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_only_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_only_verify});
    const sampled_points_only_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_only_verify}),
    );

    var proof_points = try scheme_points.proveValues(
        alloc,
        sampled_points_only,
        &channel,
    );
    defer proof_points.aux.deinit(alloc);

    var verifier_points = try Verifier.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("../../core/fri.zig").FriConfig.init(0, 2, 2),
    });
    defer verifier_points.deinit(alloc);

    var verifier_points_channel = Channel{};
    try verifier_points.commit(
        alloc,
        proof_points.proof.commitments.items[0],
        &[_]u32{2},
        &verifier_points_channel,
    );
    try verifier_points.verifyValues(
        alloc,
        sampled_points_only_verify,
        proof_points.proof,
        &verifier_points_channel,
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

    const prove_result = scheme.proveValues(alloc, sampled_points, &prover_channel);
    try std.testing.expectError(
        error.DegenerateLine,
        prove_result,
    );
}
