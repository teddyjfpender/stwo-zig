//! Commitment ingestion and streaming operations for the PCS prover.

const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const prover_circle = @import("../poly/circle/mod.zig");
const commitment_tree = @import("commitment_tree.zig");
const commit_polys = @import("commit_polys.zig");
const column_preparation = @import("columns/preparation.zig");
const deferred_commit = @import("deferred_commit.zig");
const column_storage = @import("columns/storage.zig");
const tree_builders = @import("tree_builders.zig");
const commit_dispatch = @import("commit_dispatch.zig");
const backed_columns = @import("backed_columns.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_profile = @import("stwo_prover_api").work_profile;

const M31 = m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const CoefficientRetentionPolicy = column_storage.CoefficientRetentionPolicy;
const ColumnSource = @import("column_source.zig").ColumnSource;
const TreeBuilder = tree_builders.TreeBuilder;
const StreamingTreeBuilder = tree_builders.StreamingTreeBuilder;

pub fn CommitOps(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    comptime Owner: type,
) type {
    return struct {
        const Self = Owner;
        const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);

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
            const work_recorder = if (recorder) |active|
                active.workCaptureRecorder()
            else
                null;
            self.beginShellWorkProfile(work_recorder);
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
                return commit_dispatch.commitConstant(
                    B,
                    H,
                    self,
                    allocator,
                    owned_columns,
                    work_recorder,
                    channel,
                );
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
                work_recorder,
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

            // Offer a shared backing before detaching: generic code frees each
            // column slice independently, an adopting backend keeps the arena.
            var source_arena: ?[]M31 = null;
            if (backing_buffers) |buffers| {
                const adopted = try backed_columns
                    .adoptOrDetach(B, allocator, owned_columns, buffers);
                owned_columns = adopted.columns;
                source_arena = adopted.arena;
                backing_buffers = null;
            }
            errdefer if (source_arena) |arena| allocator.free(arena);
            if (source_arena == null and deferred_commit.canDeferFirstTree(self, owned_columns) and
                deferred_commit.trySpawn(
                    B,
                    BackendCommitmentTree,
                    self,
                    allocator,
                    owned_columns,
                    work_recorder,
                )) return;
            errdefer backed_columns.freeSource(allocator, owned_columns, source_arena);
            var prepared = try column_preparation.prepareColumnsForCommitOwnedForBackend(
                B,
                allocator,
                owned_columns,
                self.config.fri_config.log_blowup_factor,
                self.coefficient_retention_policy,
                &self.twiddle_source,
                recorder,
                source_arena,
            );
            errdefer prepared.deinit(allocator);
            var merkle_commit_stage = try stage_profile.StageScope.begin(
                recorder,
                "merkle_commit",
                "Merkle commit",
            );
            defer merkle_commit_stage.end();
            if (work_recorder) |work|
                try work.expectProducer(.commitment_tree_merkle);
            // work-profile-plan:commitment-tree-merkle
            var tree = try BackendCommitmentTree.initOwnedWithBackingAndWorkRecorder(
                allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
                work_recorder,
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
            return self.commitPolysWithRecorder(allocator, polys, null, channel);
        }

        pub fn commitPolysWithRecorder(
            self: *Self,
            allocator: std.mem.Allocator,
            polys: []const prover_circle.CircleCoefficients,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            self.beginShellWorkProfile(if (recorder) |active|
                active.workCaptureRecorder()
            else
                null);
            return commit_polys.commit(
                B,
                H,
                BackendCommitmentTree,
                self,
                allocator,
                polys,
                recorder,
                channel,
            );
        }

        pub fn treeBuilder(
            self: *Self,
            allocator: std.mem.Allocator,
        ) TreeBuilder(B, H, MC, Self) {
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
        ) StreamingTreeBuilder(B, H, MC, Self) {
            return StreamingTreeBuilder(B, H, MC, Self).init(
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
            self.beginShellWorkProfile(if (recorder) |active|
                active.workCaptureRecorder()
            else
                null);
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

            var builder = StreamingTreeBuilder(B, H, MC, Self).init(
                allocator,
                self,
                effective_batch_size,
            );
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
            if (recorder) |active| {
                if (active.workCaptureRecorder()) |work|
                    try work.expectProducer(.streaming_commitment_merkle);
            }
            // work-profile-plan:streaming-commitment-merkle
            try builder.commitWithRecorder(recorder, channel);
        }
    };
}
