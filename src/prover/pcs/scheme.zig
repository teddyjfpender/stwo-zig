//! Stateful PCS commitment, opening, and proof orchestration.

const std = @import("std");
const builtin = @import("builtin");
const backend_merkle = @import("stwo_backend_contracts").merkle_ops;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const verifier_types = @import("stwo_core").verifier_types;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const twiddle_source_mod = @import("../poly/twiddle_source.zig");
const stage_profile = @import("../stage_profile.zig");
const prover_fri = @import("../fri.zig");
const commitment_tree = @import("commitment_tree.zig");
const commit_polys = @import("commit_polys.zig");
const column_preparation = @import("columns/preparation.zig");
const deferred_commit = @import("deferred_commit.zig");
const column_storage = @import("columns/storage.zig");
const pow_search = @import("proof_of_work.zig");
const sampled_value_transcript = @import("sampled_value_transcript.zig");
const sampled_value_evaluation = @import("sampled_values.zig");
const tree_builders = @import("tree_builders.zig");
const commit_dispatch = @import("commit_dispatch.zig");
const backed_columns = @import("backed_columns.zig");
const scheme_decommit = @import("scheme_decommit.zig");
const scheme_views = @import("scheme_views.zig");

pub const quotient_ops = @import("quotient_ops.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PcsConfig = pcs_core.PcsConfig;
const TreeVec = pcs_core.TreeVec;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const TwiddleSource = twiddle_source_mod.TwiddleSource;
const M31TwiddleTower = @import("../poly/twiddle_tower.zig").M31TwiddleTower;

pub const CommitmentSchemeError = error{
    ShapeMismatch,
    InvalidPreprocessedTree,
};

const CoefficientRetentionPolicy = column_storage.CoefficientRetentionPolicy;
const ColumnSource = @import("column_source.zig").ColumnSource;

pub const ColumnEvaluation = commitment_tree.ColumnEvaluation;

pub fn CommitmentTreeProver(comptime H: type) type {
    return commitment_tree.CommitmentTreeProver(H);
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

pub fn CommitmentSchemeProver(comptime B: type, comptime H: type, comptime MC: type) type {
    comptime backend_merkle.assertMerkleOps(B, H);
    const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);
    return struct {
        trees: std.ArrayListUnmanaged(BackendCommitmentTree),
        config: PcsConfig,
        coefficient_retention_policy: CoefficientRetentionPolicy,
        twiddle_source: TwiddleSource,
        pending_commit: ?deferred_commit.Pending(BackendCommitmentTree),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, config: PcsConfig) !Self {
            return initWithTwiddleSource(config, TwiddleSource.initOwned(allocator));
        }
        pub fn initWithTwiddleTower(config: PcsConfig, tower: *const M31TwiddleTower) Self {
            return initWithTwiddleSource(config, TwiddleSource.initBorrowed(tower));
        }
        fn initWithTwiddleSource(config: PcsConfig, twiddle_source: TwiddleSource) Self {
            return .{
                .trees = .{},
                .config = config,
                .coefficient_retention_policy = .always,
                .twiddle_source = twiddle_source,
                .pending_commit = null,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            deferred_commit.discard(self, allocator);
            for (self.trees.items) |*tree| tree.deinit(allocator);
            self.trees.deinit(allocator);
            self.twiddle_source.deinit(allocator);
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
            var prepared = try column_preparation.prepareColumnsForCommitBorrowedForBackend(
                B,
                allocator,
                columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_source,
            );
            errdefer prepared.deinit(allocator);

            var tree = try BackendCommitmentTree.initOwnedWithBacking(
                allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
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

        /// Default batch size for streaming column commitment.
        const streaming_batch_size: usize = 64;
        /// Column count threshold above which commitOwnedWithRecorder
        /// automatically uses the streaming path.  Below this threshold
        /// the monolithic path is used (the overhead of streaming state
        /// management is not worthwhile for small column sets).
        const streaming_column_threshold: usize = 128;

        pub fn commitOwnedWithRecorder(
            self: *Self,
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            return self.commitOwnedWithRecorderAndBacking(
                allocator,
                owned_columns,
                null,
                recorder,
                channel,
            );
        }

        /// Ownership-preserving commit for columns that borrow one or more
        /// shared allocations. Backends may adopt those allocations; generic
        /// paths detach them into ordinary per-column ownership first.
        pub fn commitOwnedWithRecorderAndBacking(
            self: *Self,
            allocator: std.mem.Allocator,
            input_columns: []ColumnEvaluation,
            input_backing_buffers: ?[][]M31,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            return self.commitOwnedPreparedWithRecorderAndBacking(
                allocator,
                input_columns,
                input_backing_buffers,
                .materialized,
                recorder,
                channel,
            );
        }

        /// Commits columns whose values may be represented by an explicit
        /// structural producer. Adopting backends can encode that producer in
        /// the commitment epoch; all other paths materialize it before reading
        /// or detaching the values.
        pub fn commitOwnedPreparedWithRecorderAndBacking(
            self: *Self,
            allocator: std.mem.Allocator,
            input_columns: []ColumnEvaluation,
            input_backing_buffers: ?[][]M31,
            input_source: ColumnSource,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            var owned_columns = input_columns;
            var backing_buffers = input_backing_buffers;
            const source = input_source;
            if (source.isMaterialized() and column_preparation.columnEvaluationsAreConstant(owned_columns)) {
                if (backing_buffers) |buffers| {
                    const detached = backed_columns.detach(allocator, owned_columns) catch |err| {
                        backed_columns.free(allocator, owned_columns, buffers);
                        return err;
                    };
                    backed_columns.free(allocator, owned_columns, buffers);
                    owned_columns = detached;
                    backing_buffers = null;
                }
                return commit_dispatch.commitConstant(B, H, self, allocator, owned_columns, channel);
            }
            // Auto-dispatch to streaming for large column sets (bounds peak memory).
            const backend_prefers_monolithic = comptime @hasDecl(B, "preferMonolithicCommit") and B.preferMonolithicCommit;
            if (source.isMaterialized() and owned_columns.len >= streaming_column_threshold and
                !backend_prefers_monolithic)
            {
                if (backing_buffers) |buffers| {
                    const detached = backed_columns.detach(allocator, owned_columns) catch |err| {
                        backed_columns.free(allocator, owned_columns, buffers);
                        return err;
                    };
                    backed_columns.free(allocator, owned_columns, buffers);
                    owned_columns = detached;
                    backing_buffers = null;
                }
                return self.commitOwnedStreamingWithRecorder(
                    allocator,
                    owned_columns,
                    streaming_batch_size,
                    recorder,
                    channel,
                );
            }
            if (try commit_dispatch.tryPrecommitted(
                B,
                H,
                allocator,
                owned_columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_source,
                backing_buffers,
                source,
            )) |committed| {
                var tree = committed;
                errdefer tree.deinit(allocator);
                if (comptime builtin.is_test and @hasDecl(B, "failAfterOwnershipTransferForTesting")) {
                    try B.failAfterOwnershipTransferForTesting();
                }
                return self.appendCommittedTree(allocator, tree, channel);
            }

            if (!source.isMaterialized()) {
                if (comptime !@hasDecl(B, "materializeColumnSource")) {
                    if (backing_buffers) |buffers|
                        backed_columns.free(allocator, owned_columns, buffers)
                    else
                        column_storage.freeOwnedColumnEvaluations(allocator, owned_columns);
                    return error.UnsupportedColumnSource;
                }
                B.materializeColumnSource(owned_columns, source) catch |err| {
                    if (backing_buffers) |buffers|
                        backed_columns.free(allocator, owned_columns, buffers)
                    else
                        column_storage.freeOwnedColumnEvaluations(allocator, owned_columns);
                    return err;
                };
            }

            // A shared arena cannot flow into generic code that frees each
            // slice independently. Detach only after every adopting backend
            // has declined without mutation.
            if (backing_buffers) |buffers| {
                const detached = backed_columns.detach(allocator, owned_columns) catch |err| {
                    backed_columns.free(allocator, owned_columns, buffers);
                    return err;
                };
                backed_columns.free(allocator, owned_columns, buffers);
                owned_columns = detached;
                backing_buffers = null;
            }

            if (deferred_commit.canDeferFirstTree(self, owned_columns) and
                deferred_commit.trySpawn(B, BackendCommitmentTree, self, allocator, owned_columns)) return;
            errdefer column_storage.freeOwnedColumnEvaluations(allocator, owned_columns);
            var prepared = try column_preparation.prepareColumnsForCommitOwnedForBackend(
                B,
                allocator,
                owned_columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_source,
                recorder,
            );
            errdefer prepared.deinit(allocator);
            var merkle_commit_stage = try stage_profile.StageScope.begin(
                recorder,
                "merkle_commit",
                "Merkle commit",
            );
            defer merkle_commit_stage.end();
            var tree = try BackendCommitmentTree.initOwnedWithBacking(
                allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
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
            return commit_polys.commit(
                B,
                H,
                BackendCommitmentTree,
                self,
                allocator,
                polys,
                channel,
            );
        }

        pub fn treeBuilder(self: *Self, allocator: std.mem.Allocator) TreeBuilder(B, H, MC) {
            return .{
                .allocator = allocator,
                .tree_index = self.trees.items.len,
                .commitment_scheme = self,
                .columns = std.ArrayList(ColumnEvaluation).empty,
            };
        }

        /// Returns a `StreamingTreeBuilder` that commits columns in
        /// configurable batches, reducing peak memory.
        ///
        /// Usage:
        ///   1. Call `streamingTreeBuilder()` to obtain a builder.
        ///   2. Call `builder.addColumns(batch)` for each batch of
        ///      `ColumnEvaluation` (owned values).  The batch data is prepared
        ///      (interpolated + extended) and retained for decommitment.
        ///   3. Call `builder.commit(channel)` to hash the complete sorted shape,
        ///      finalise the Merkle tree, and append it to the scheme.
        ///
        /// The final Merkle root is bit-identical to `commitOwned()`.
        pub fn streamingTreeBuilder(
            self: *Self,
            allocator: std.mem.Allocator,
            batch_size: u32,
        ) StreamingTreeBuilder(B, H, MC) {
            return StreamingTreeBuilder(B, H, MC).init(
                allocator,
                self,
                batch_size,
            );
        }

        /// Commits owned evaluation columns in streaming batches to reduce peak
        /// memory. Semantically identical to `commitOwned()` but prepares
        /// columns in groups of `batch_size` before one shape-aware leaf pass.
        ///
        /// `batch_size` controls the number of columns prepared in each round.
        /// A value of 0 uses the default (64).
        pub fn commitOwnedStreaming(
            self: *Self,
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            batch_size: u32,
            channel: anytype,
        ) !void {
            return self.commitOwnedStreamingWithRecorder(
                allocator,
                owned_columns,
                batch_size,
                null,
                channel,
            );
        }

        pub fn commitOwnedStreamingWithRecorder(
            self: *Self,
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            batch_size_arg: u32,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            const effective_batch_size: usize = if (batch_size_arg == 0) 64 else @as(usize, batch_size_arg);

            const ColumnOrder = struct {
                columns: []const ColumnEvaluation,

                fn lessThan(context: @This(), lhs: usize, rhs: usize) bool {
                    const lhs_log_size = context.columns[lhs].log_size;
                    const rhs_log_size = context.columns[rhs].log_size;
                    return lhs_log_size < rhs_log_size or
                        (lhs_log_size == rhs_log_size and lhs < rhs);
                }
            };
            const order = try allocator.alloc(usize, owned_columns.len);
            defer allocator.free(order);
            for (order, 0..) |*index, i| index.* = i;
            std.sort.heap(
                usize,
                order,
                ColumnOrder{ .columns = owned_columns },
                ColumnOrder.lessThan,
            );

            var builder = StreamingTreeBuilder(B, H, MC).init(allocator, self, effective_batch_size);
            errdefer builder.deinit();

            // Each batch moves entries out of `owned_columns`; the builder owns
            // consumed entries and the error paths below free the remainder.
            var consumed: usize = 0;
            while (consumed < owned_columns.len) {
                const end = @min(owned_columns.len, consumed + effective_batch_size);
                const batch_len = end - consumed;

                const batch = allocator.alloc(ColumnEvaluation, batch_len) catch |err| {
                    for (owned_columns) |col| {
                        if (col.values.len > 0) allocator.free(col.values);
                    }
                    allocator.free(owned_columns);
                    return err;
                };
                for (order[consumed..end], 0..) |original_index, batch_index| {
                    batch[batch_index] = owned_columns[original_index];
                    owned_columns[original_index].values = &[_]M31{};
                }

                tree_builders.addColumnsOwnedIndexed(
                    &builder,
                    batch,
                    order[consumed..end],
                    recorder,
                ) catch |err| {
                    // batch is owned by addColumnsOwned on success.
                    // On error, addColumnsOwned's errdefer handles the batch
                    // via prepareColumnsForCommitOwned's errdefer.
                    for (owned_columns) |col| {
                        if (col.values.len > 0) allocator.free(col.values);
                    }
                    allocator.free(owned_columns);
                    return err;
                };
                consumed = end;
            }

            // All column values have been transferred to the builder.
            allocator.free(owned_columns);

            var merkle_commit_stage = try stage_profile.StageScope.begin(
                recorder,
                "merkle_commit",
                "Merkle commit",
            );
            defer merkle_commit_stage.end();
            try builder.commit(channel);
        }

        pub fn roots(self: *Self, allocator: std.mem.Allocator) !TreeVec(H.Hash) {
            try deferred_commit.resolveObserved(self, allocator);
            return scheme_views.roots(H, self.*, allocator);
        }

        /// Returns committed columns as prover-air `Poly` views.
        ///
        /// The returned wrappers borrow underlying column storage from the commitment scheme.
        pub fn polynomials(
            self: Self,
            allocator: std.mem.Allocator,
        ) !TreeVec([]const @import("../air/component_prover.zig").Poly) {
            return scheme_views.polynomials(self, allocator);
        }

        pub fn trace(
            self: Self,
            allocator: std.mem.Allocator,
        ) !@import("../air/component_prover.zig").Trace {
            return scheme_views.trace(self, allocator);
        }

        pub fn backendResidencyHandles(self: Self, allocator: std.mem.Allocator) ![]?*anyopaque {
            return scheme_views.backendResidencyHandles(B, H, self, allocator);
        }

        pub fn columnLogSizes(self: Self, allocator: std.mem.Allocator) !TreeVec([]u32) {
            return scheme_views.columnLogSizes(self, allocator);
        }

        pub fn buildQueryPositionsTree(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            lifting_log_size: u32,
        ) !TreeVec([]usize) {
            return scheme_views.buildQueryPositionsTree(
                self,
                allocator,
                query_positions,
                lifting_log_size,
            );
        }

        pub fn decommitByTreePositions(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions_tree: TreeVec([]const usize),
        ) !TreeDecommitmentResult(H) {
            return scheme_decommit.decommit(
                H,
                TreeDecommitmentResult(H),
                self,
                allocator,
                query_positions_tree,
            );
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
            var owns_scheme = true;
            errdefer if (owns_scheme) scheme.deinit(allocator);

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

            // The downstream method consumes the scheme on both success and error.
            owns_scheme = false;
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
                try sampled_value_transcript.mixIntoChannel(allocator, channel, sampled_values_owned);
            }

            const random_coeff = channel.drawSecureFelt();
            const lifting_log_size = try scheme.maxTreeLogSize();
            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
            var fri_prover = blk: {
                var fri_quotient_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "fri_quotient_build_and_commit",
                    "FRI quotient build + commit (lazy)",
                );
                defer fri_quotient_stage.end();

                const borrowed_columns_items = try allocator.alloc([]const ColumnEvaluation, scheme.trees.items.len);
                defer allocator.free(borrowed_columns_items);
                for (scheme.trees.items, 0..) |tree, i| {
                    borrowed_columns_items[i] = tree.columns;
                }

                var residency_storage: ?[]*anyopaque = null;
                defer if (residency_storage) |handles| allocator.free(handles);
                var residency_handles: []const *anyopaque = &.{};
                if (comptime B != void and @hasDecl(B, "quotientResidencyHandle")) {
                    const handles = try allocator.alloc(*anyopaque, scheme.trees.items.len);
                    residency_storage = handles;
                    var resident_count: usize = 0;
                    for (scheme.trees.items) |tree| {
                        if (B.quotientResidencyHandle(H, tree.commitment)) |handle| {
                            handles[resident_count] = handle;
                            resident_count += 1;
                        }
                    }
                    residency_handles = handles[0..resident_count];
                }

                var provider = try quotient_ops.LazyQuotientProvider.initForBackend(
                    B,
                    allocator,
                    TreeVec([]const ColumnEvaluation).initOwned(borrowed_columns_items),
                    sampled_points_owned,
                    sampled_values_owned,
                    random_coeff,
                    lifting_log_size,
                );
                defer provider.deinit(allocator);
                provider.setBackendResidencyHandles(residency_handles);

                const fold_tree = try scheme.twiddle_source.get(allocator, lifting_log_size);
                break :blk try prover_fri.FriProver(B, H, MC).commitLazy(
                    allocator,
                    channel,
                    scheme.config.fri_config,
                    domain,
                    &provider,
                    fold_tree.itwiddles,
                );
            };

            const proof_of_work = blk: {
                var proof_of_work_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "proof_of_work",
                    "Proof of work",
                );
                defer proof_of_work_stage.end();
                const nonce = pow_search.grind(channel, scheme.config.pow_bits);
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

        pub fn appendCommittedTree(
            self: *Self,
            allocator: std.mem.Allocator,
            tree: BackendCommitmentTree,
            channel: anytype,
        ) !void {
            return tree_builders.appendCommittedTree(MC, self, allocator, tree, channel);
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
            return sampled_value_evaluation.evaluateAndRelease(
                B,
                H,
                allocator,
                self.trees.items,
                sampled_points,
                lifting_log_size,
            );
        }
    };
}

pub fn TreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return tree_builders.TreeBuilder(B, H, MC, CommitmentSchemeProver(B, H, MC));
}

pub fn StreamingTreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return tree_builders.StreamingTreeBuilder(B, H, MC, CommitmentSchemeProver(B, H, MC));
}
