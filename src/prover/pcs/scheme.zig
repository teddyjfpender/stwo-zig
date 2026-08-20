//! Stateful PCS commitment, opening, and proof orchestration.

const std = @import("std");
const builtin = @import("builtin");
const backend_merkle = @import("stwo_backend_contracts").merkle_ops;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const core_fri = @import("stwo_core").fri;
const pcs_core = @import("stwo_core").pcs;
const verifier_types = @import("stwo_core").verifier_types;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const twiddle_source_mod = @import("../poly/twiddle_source.zig");
const work_pool = @import("../work_pool.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_profile = @import("stwo_prover_api").work_profile;
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
const shell_work_profile = @import("shell_work_profile.zig");

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
        shell_preopening_audit: shell_work_profile.PreOpeningAudit,

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
                .shell_preopening_audit = .{},
            };
        }

        /// Arms the cold shell audit before the first profiled commitment.
        /// Starting after a tree exists (or is pending) remains observable and
        /// makes final publication fail closed.
        pub fn beginShellWorkProfile(self: *Self, work_recorder: ?*work_profile.Recorder(true)) void {
            const active = work_recorder orelse return;
            self.shell_preopening_audit.begin(
                self.trees.items.len,
                self.pending_commit != null,
            );
            if (!self.shell_preopening_audit.complete) active.markIncomplete();
        }

        pub fn observePreOpeningRootMix(self: *Self, ordinal: usize, root: []const u8) void {
            self.shell_preopening_audit.observeRootMixed(ordinal, root);
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

        /// Selects whether committed evaluation columns retain a second,
        /// coefficient-form copy until the opening phase.
        ///
        /// `.never` bounds commitment residency at the cost of evaluating
        /// sampled values from the committed extended-domain columns. This
        /// does not change commitments, Fiat-Shamir inputs, or proof bytes.
        pub fn setCoefficientRetentionPolicy(
            self: *Self,
            policy: CoefficientRetentionPolicy,
        ) void {
            self.coefficient_retention_policy = policy;
        }

        const CommitOps = @import("commit_ops.zig").CommitOps(B, H, MC, Self);
        pub const commit = CommitOps.commit;
        pub const commitOwned = CommitOps.commitOwned;
        pub const commitOwnedWithRecorder = CommitOps.commitOwnedWithRecorder;
        pub const commitOwnedWithRecorderAndBacking = CommitOps.commitOwnedWithRecorderAndBacking;
        pub const commitOwnedPreparedWithRecorderAndBacking = CommitOps.commitOwnedPreparedWithRecorderAndBacking;
        pub const commitPolys = CommitOps.commitPolys;
        pub const commitPolysWithRecorder = CommitOps.commitPolysWithRecorder;
        pub const treeBuilder = CommitOps.treeBuilder;
        pub const streamingTreeBuilder = CommitOps.streamingTreeBuilder;
        pub const commitOwnedStreaming = CommitOps.commitOwnedStreaming;
        pub const commitOwnedStreamingWithRecorder = CommitOps.commitOwnedStreamingWithRecorder;
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
            var sampled_points_owned = sampled_points;
            var owns_sampled_points = true;
            errdefer if (owns_sampled_points) sampled_points_owned.deinitDeep(allocator);

            try work_pool.observeProofPoolStageForTest(
                .openings,
                work_pool.getGlobalPool(),
            );

            const lifting_log_size = try scheme.proofLiftingLogSize();
            const sampled_values = blk: {
                var sampled_value_eval_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "sampled_value_evaluation",
                    "Sampled-value evaluation",
                );
                defer sampled_value_eval_stage.end();
                break :blk try scheme.evaluateSampledValuesAndRelease(
                    allocator,
                    sampled_points_owned,
                    lifting_log_size,
                    recorder,
                );
            };

            // The downstream method consumes both owners on success and error.
            owns_scheme = false;
            owns_sampled_points = false;
            return scheme.proveValuesFromSamplesWithRecorder(
                allocator,
                sampled_points_owned,
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

            const work_recorder = if (recorder) |active|
                active.workCaptureRecorder()
            else
                null;
            if (work_recorder) |work| {
                try work.expectProducer(.pcs_transcript_shell);
                // work-profile-plan:pcs-transcript-shell
            }

            if (scheme.trees.items.len != sampled_points_owned.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }
            if (scheme.trees.items.len != sampled_values_owned.items.len) {
                return CommitmentSchemeError.ShapeMismatch;
            }

            var sampled_column_count: usize = 0;
            var sampled_value_count: usize = 0;
            for (scheme.trees.items, sampled_points_owned.items, sampled_values_owned.items) |tree, tree_points, tree_values| {
                if (tree.columns.len != tree_points.len) return CommitmentSchemeError.ShapeMismatch;
                if (tree.columns.len != tree_values.len) return CommitmentSchemeError.ShapeMismatch;
                sampled_column_count = std.math.add(
                    usize,
                    sampled_column_count,
                    tree_values.len,
                ) catch return CommitmentSchemeError.ShapeMismatch;
                for (tree_values) |column_values| {
                    sampled_value_count = std.math.add(
                        usize,
                        sampled_value_count,
                        column_values.len,
                    ) catch return CommitmentSchemeError.ShapeMismatch;
                }
            }

            var shell_audit: ?shell_work_profile.Audit = if (work_recorder != null)
                shell_work_profile.Audit.init(
                    @TypeOf(channel.*),
                    H,
                    MC,
                    scheme.trees.items.len,
                    sampled_column_count,
                    sampled_value_count,
                    &scheme.shell_preopening_audit,
                ) catch blk: {
                    work_recorder.?.markIncomplete();
                    break :blk null;
                }
            else
                null;

            {
                var sampled_value_mix_stage = try stage_profile.StageScope.begin(
                    recorder,
                    "sampled_value_channel_mix",
                    "Sampled-value channel mix",
                );
                defer sampled_value_mix_stage.end();
                try sampled_value_transcript.mixIntoChannel(allocator, channel, sampled_values_owned);
            }
            if (shell_audit) |*audit| {
                audit.observeSampledValuesMixed() catch work_recorder.?.markIncomplete();
            }

            const random_coeff = channel.drawSecureFelt();
            if (shell_audit) |*audit| {
                audit.observeCoefficientDrawn() catch work_recorder.?.markIncomplete();
            }

            const lifting_log_size = try scheme.proofLiftingLogSize();
            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

            var fri_root_mix_capture = shell_work_profile.FriRootMixCapture{};
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

                const fri_work_recorder = work_recorder;
                if (fri_work_recorder) |work| {
                    try work.expectProducer(.quotient_sample_preparation);
                    // work-profile-plan:quotient-sample-preparation
                    try work.expectProducer(.quotient_row_execution);
                    // work-profile-plan:quotient-row-execution
                    try work.expectProducer(.fri_protocol);
                    // work-profile-plan:fri-protocol
                }

                var provider = try quotient_ops.LazyQuotientProvider.initForBackendWithWorkRecorder(
                    B,
                    allocator,
                    TreeVec([]const ColumnEvaluation).initOwned(borrowed_columns_items),
                    sampled_points_owned,
                    sampled_values_owned,
                    random_coeff,
                    lifting_log_size,
                    fri_work_recorder,
                );
                defer provider.deinit(allocator);
                provider.setBackendResidencyHandles(residency_handles);

                var result = try prover_fri.FriProver(B, H, MC).commitLazyWithWorkRecorderAndRootMixCapture(
                    allocator,
                    channel,
                    scheme.config.fri_config,
                    domain,
                    &provider,
                    fri_work_recorder,
                    if (shell_audit != null) &fri_root_mix_capture else null,
                );
                errdefer result.deinit(allocator);
                break :blk result;
            };
            if (shell_audit) |*audit| {
                const fri_layer_count = std.math.add(
                    usize,
                    fri_prover.inner_layers.len,
                    1,
                ) catch 0;
                if (fri_root_mix_capture.receipt) |root_mix_receipt| {
                    audit.observeFriCommitted(
                        fri_layer_count,
                        root_mix_receipt,
                    ) catch work_recorder.?.markIncomplete();
                } else work_recorder.?.markIncomplete();
            }

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
            if (shell_audit) |*audit| {
                audit.observeProofOfWorkMixed(
                    scheme.config.pow_bits,
                    proof_of_work,
                ) catch work_recorder.?.markIncomplete();
            }

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
            if (shell_audit) |*audit| {
                audit.observeFriDecommitted(
                    fri_decommit.unsorted_query_locations.len,
                    fri_decommit.query_positions.len,
                ) catch work_recorder.?.markIncomplete();
            }

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
            if (shell_audit) |*audit| {
                audit.observeTraceDecommitted(
                    trace_decommit.decommitments.items.len,
                ) catch work_recorder.?.markIncomplete();
            }

            var commitments = try scheme.roots(allocator);
            errdefer commitments.deinit(allocator);
            if (shell_audit) |*audit| {
                audit.observeCommitmentRootsMaterialized(commitments.items.len) catch
                    work_recorder.?.markIncomplete();
            }

            // `query_positions` are only needed for prover-side decommit orchestration.
            allocator.free(fri_decommit.query_positions);
            fri_decommit.query_positions = &[_]usize{};

            const result: pcs_core.ExtendedCommitmentSchemeProof(H) = .{
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
            if (shell_audit) |*audit| {
                const receipt = audit.finish(result.proof.commitments.items.len) catch {
                    work_recorder.?.markIncomplete();
                    return result;
                };
                receipt.validate() catch {
                    work_recorder.?.markIncomplete();
                    return result;
                };
                work_recorder.?.recordCompletedDelta(.{
                    .site = .pcs_transcript_shell,
                    .producer = work_profile.boundaryForSite(.pcs_transcript_shell),
                    .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
                        work_profile.SourceMask.one(.field_multiplications).bits |
                        work_profile.SourceMask.one(.field_inversions).bits },
                }) catch {
                    work_recorder.?.markIncomplete();
                    return result;
                };
                if (comptime builtin.is_test)
                    shell_work_profile.testing.observeAcceptedReceipt(receipt);
                // work-profile-complete:pcs-transcript-shell
            }
            return result;
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

        /// The final composition tree sets the proof domain. Earlier trees may
        /// contain larger columns when those columns are left unsampled.
        fn proofLiftingLogSize(self: Self) !u32 {
            if (self.trees.items.len == 0) return CommitmentSchemeError.ShapeMismatch;
            const final_tree = self.trees.items[self.trees.items.len - 1];
            if (final_tree.columns.len == 0) return CommitmentSchemeError.ShapeMismatch;
            return maxLogSize(final_tree.columns);
        }

        fn evaluateSampledValuesAndRelease(
            self: *Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            lifting_log_size: u32,
            recorder: ?*stage_profile.Recorder,
        ) !TreeVec([][]QM31) {
            const work_recorder = if (recorder) |active|
                active.workCaptureRecorder()
            else
                null;
            return sampled_value_evaluation.evaluateAndReleaseWithWorkRecorder(
                B,
                H,
                allocator,
                self.trees.items,
                sampled_points,
                lifting_log_size,
                work_recorder,
            );
        }
    };
}

fn friMerkleCompressions(
    comptime B: type,
    prover: anytype,
    config: core_fri.FriConfig,
) !u64 {
    var total: u64 = 0;
    const first_packed = friLayerUsesPackedLeaves(
        prover.first_layer.column.len(),
        config.fold_step,
    );
    const first_reuses_constant = if (comptime @hasDecl(B, "commitLazyMerkle"))
        if (first_packed)
            B.reuses_constant_merkle_parents
        else
            B.lazy_merkle_reuses_constant_parents
    else
        B.reuses_constant_merkle_parents;
    total = try addMerkleCompressions(
        total,
        try friLayerMerkleCompressions(
            prover.first_layer.column,
            first_packed,
            first_reuses_constant,
        ),
    );

    for (prover.inner_layers) |layer| {
        const uses_packed_leaves = friLayerUsesPackedLeaves(
            layer.column.len(),
            layer.fold_step,
        );
        total = try addMerkleCompressions(
            total,
            try friLayerMerkleCompressions(
                layer.column,
                uses_packed_leaves,
                B.reuses_constant_merkle_parents,
            ),
        );
    }
    return total;
}

fn friLayerUsesPackedLeaves(column_len: usize, fold_step: u32) bool {
    const packed_leaf_size = @as(usize, 1) <<
        @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
    return fold_step > 1 and column_len >= packed_leaf_size and
        std.math.isPowerOfTwo(column_len);
}

fn friLayerMerkleCompressions(
    column: anytype,
    uses_packed_leaves: bool,
    reuses_constant_parents: bool,
) !u64 {
    const packed_leaf_size = @as(usize, 1) <<
        @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
    if (column.len() == 0 or !std.math.isPowerOfTwo(column.len()))
        return error.InvalidCounterGroup;
    const leaf_count = if (uses_packed_leaves)
        column.len() / packed_leaf_size
    else
        column.len();
    const encoded_leaf_count = std.math.cast(u64, leaf_count) orelse
        return error.CounterOverflow;
    return work_profile.logicalMerkleCompressions(
        encoded_leaf_count,
        reuses_constant_parents and
            friColumnIsMerkleConstant(column, uses_packed_leaves),
    );
}

fn friColumnIsMerkleConstant(column: anytype, uses_packed_leaves: bool) bool {
    const packed_leaf_size = @as(usize, 1) <<
        @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
    const leaf_count = if (uses_packed_leaves)
        column.len() / packed_leaf_size
    else
        column.len();
    if (leaf_count == 0) return false;

    for (column.columns) |coordinate| {
        const values_per_leaf = if (uses_packed_leaves) packed_leaf_size else 1;
        for (0..values_per_leaf) |offset| {
            const first = coordinate[offset];
            for (1..leaf_count) |leaf| {
                const index = leaf * values_per_leaf + offset;
                if (!coordinate[index].eql(first)) return false;
            }
        }
    }
    return true;
}

fn addMerkleCompressions(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.CounterOverflow;
}

pub fn TreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return tree_builders.TreeBuilder(B, H, MC, CommitmentSchemeProver(B, H, MC));
}

pub fn StreamingTreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return tree_builders.StreamingTreeBuilder(B, H, MC, CommitmentSchemeProver(B, H, MC));
}

test "FRI Merkle work follows packed-leaf and constant-parent execution" {
    const TestColumn = struct {
        columns: [qm31.SECURE_EXTENSION_DEGREE][]const M31,

        fn len(self: @This()) usize {
            return self.columns[0].len;
        }
    };
    const constant_values = [_]M31{M31.fromCanonical(7)} ** 8;
    const varying_values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    const constant = TestColumn{ .columns = .{
        &constant_values,
        &constant_values,
        &constant_values,
        &constant_values,
    } };
    const varying = TestColumn{ .columns = .{
        &varying_values,
        &constant_values,
        &constant_values,
        &constant_values,
    } };

    try std.testing.expect(friColumnIsMerkleConstant(constant, false));
    try std.testing.expect(!friColumnIsMerkleConstant(varying, false));
    try std.testing.expectEqual(
        @as(u64, 3),
        try friLayerMerkleCompressions(constant, false, true),
    );
    try std.testing.expectEqual(
        @as(u64, 7),
        try friLayerMerkleCompressions(varying, false, true),
    );

    // Four evaluation rows become one packed leaf. Constant packed columns
    // therefore need zero parent compressions, while two varying packed
    // leaves require exactly one.
    try std.testing.expect(friLayerUsesPackedLeaves(8, 2));
    try std.testing.expectEqual(
        @as(u64, 0),
        try friLayerMerkleCompressions(constant, true, true),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        try friLayerMerkleCompressions(varying, true, true),
    );
}
