//! Owned and streaming PCS tree construction.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const prover_circle = @import("../poly/circle/mod.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_profile = @import("stwo_prover_api").work_profile;
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");
const commitment_tree = @import("commitment_tree.zig");
const column_preparation = @import("columns/preparation.zig");
const column_storage = @import("columns/storage.zig");

const M31 = m31.M31;
const TreeSubspan = pcs_core.TreeSubspan;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const CoefficientRetentionPolicy = column_storage.CoefficientRetentionPolicy;

const deferred_commit = @import("deferred_commit.zig");
const cached_tree = @import("merkle_cached_tree.zig");

const PCS_COLUMN_HISTOGRAM_ENV = "STWO_ZIG_PCS_COLUMN_HISTOGRAM";
const bounded_prefix_state_budget_bytes: usize = 96 * 1024 * 1024;
var histogram_print_mutex: std.Thread.Mutex = .{};

fn emitColumnHistogram(comptime H: type, sorted: anytype) void {
    if (!std.process.hasEnvVarConstant(PCS_COLUMN_HISTOGRAM_ENV)) return;
    histogram_print_mutex.lock();
    defer histogram_print_mutex.unlock();

    std.debug.print(
        "pcs_column_histogram hasher={s} columns={d} groups=",
        .{ @typeName(H), sorted.len },
    );
    var group_start: usize = 0;
    while (group_start < sorted.len) {
        const log_size = sorted[group_start].log_size;
        var group_end = group_start + 1;
        while (group_end < sorted.len and sorted[group_end].log_size == log_size) {
            group_end += 1;
        }
        std.debug.print(
            "{s}{d}:{d}",
            .{ if (group_start == 0) "" else ",", log_size, group_end - group_start },
        );
        group_start = group_end;
    }
    std.debug.print("\n", .{});
}

fn emitBoundedPrefixStats(stats: anytype) void {
    if (!std.process.hasEnvVarConstant(PCS_COLUMN_HISTOGRAM_ENV)) return;
    histogram_print_mutex.lock();
    defer histogram_print_mutex.unlock();
    std.debug.print(
        "pcs_bounded_prefix final_log={d} prefix_log={d} prefix_columns={d} " ++
            "tail_columns={d} prefix_state_bytes={d} leaf_bytes={d} " ++
            "leaf_phase_peak_bytes={d} repeated_tail_absorptions={d} tail_cache_bytes={d}\n",
        .{
            stats.final_log_size,
            stats.prefix_log_size,
            stats.prefix_column_count,
            stats.tail_column_count,
            stats.prefix_state_bytes,
            stats.leaf_layer_bytes,
            stats.leaf_phase_peak_bytes,
            stats.repeated_tail_absorptions,
            stats.tail_cache_bytes,
        },
    );
}

pub fn appendCommittedTree(
    comptime MC: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    tree: anytype,
    channel: anytype,
) !void {
    // A deferred first-tree build (if any) joins and mixes its root here,
    // before this tree is appended — preserving the sequential mix order.
    try deferred_commit.resolve(MC, scheme, allocator, channel);
    var retained = tree;
    // Admit capacity first. Compaction is fail-atomic, so an error leaves
    // the caller's complete tree ownership intact.
    try scheme.trees.ensureUnusedCapacity(allocator, 1);
    if (comptime @hasField(@TypeOf(scheme.*), "compact_polynomial_storage")) {
        if (scheme.compact_polynomial_storage)
            try retained.compactPolynomialStorage(allocator, scheme.compact_polynomial_min_log_size);
    }
    scheme.trees.appendAssumeCapacity(retained);
    const root = retained.root();
    MC.mixRoot(channel, root);
    if (comptime @hasDecl(@TypeOf(scheme.*), "observePreOpeningRootMix")) {
        scheme.observePreOpeningRootMix(
            scheme.trees.items.len - 1,
            std.mem.asBytes(&root),
        );
    }
}

pub fn addColumnsOwnedIndexed(
    builder: anytype,
    owned_columns: []ColumnEvaluation,
    original_indices: []const usize,
    recorder: ?*stage_profile.Recorder,
) !void {
    return builder.addColumnsOwnedIndexed(owned_columns, original_indices, recorder);
}

pub fn TreeBuilder(comptime B: type, comptime H: type, comptime MC: type, comptime Scheme: type) type {
    return struct {
        allocator: std.mem.Allocator,
        tree_index: usize,
        commitment_scheme: *Scheme,
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
            if (self.commitment_scheme.retained_column_allocator != null)
                return self.commitment_scheme.commitOwnedStreaming(self.allocator, base_columns, 64, channel);
            var tree = blk: {
                var prepared = column_preparation.prepareColumnsForCommitOwnedForBackend(
                    B,
                    self.allocator,
                    base_columns,
                    self.commitment_scheme.config.fri_config.log_blowup_factor,
                    self.commitment_scheme.coefficient_retention_policy,
                    &self.commitment_scheme.twiddle_source,
                    null,
                    null,
                ) catch |err| {
                    column_storage.freeOwnedColumnEvaluations(self.allocator, base_columns);
                    return err;
                };
                errdefer prepared.deinit(self.allocator);
                break :blk try commitment_tree.CommitmentTreeProverForBackend(B, H).initPrepared(self.allocator, &prepared, null);
            };
            errdefer tree.deinit(self.allocator);
            try appendCommittedTree(MC, self.commitment_scheme, self.allocator, tree, channel);
        }
    };
}

fn adoptStreamingCommitment(
    comptime B: type,
    comptime H: type,
    host_tree: vcs_lifted_prover.MerkleProverLifted(H),
) !B.MerkleTree(H) {
    if (comptime B.MerkleTree(H) == vcs_lifted_prover.MerkleProverLifted(H)) {
        return host_tree;
    }
    if (comptime @hasDecl(B, "adoptHostMerkle")) {
        return B.adoptHostMerkle(H, host_tree);
    }
    @compileError("Backend-specific Merkle trees require `adoptHostMerkle` for streaming PCS commits.");
}

/// A streaming tree builder that prepares columns in configurable batches,
/// then incrementally hashes the complete height-sorted column set. Retaining
/// the complete shape enables sparse high-domain tail finalization.
///
/// The resulting Merkle root is bit-identical to building the tree from all
/// columns at once.
pub fn StreamingTreeBuilder(comptime B: type, comptime H: type, comptime MC: type, comptime Scheme: type) type {
    const MerkleProver = vcs_lifted_prover.MerkleProverLifted(H);
    return struct {
        allocator: std.mem.Allocator,
        commitment_scheme: *Scheme,
        batch_size: usize,

        /// Streaming Merkle committer used for the height-grouped leaf pass.
        streaming_committer: MerkleProver.StreamingCommitter,

        /// Columns retained for later decommitment and sampled-value evaluation.
        /// Each entry stores the *extended* column values and their log_size.
        retained_columns: std.ArrayList(ColumnEvaluation),
        retained_column_allocator: ?std.mem.Allocator,
        retained_column_backings: std.ArrayList(commitment_tree.ColumnBacking) = .empty,

        /// Original PCS position for each retained column. Streaming hashes
        /// columns in log-size order, then restores this order before commit.
        retained_column_indices: std.ArrayList(usize),

        /// Coefficient polynomials retained for sampled-value evaluation
        /// (only when the retention policy says to keep them).
        retained_coefficients: std.ArrayList(prover_circle.CircleCoefficients),
        retained_coefficient_buffers: std.ArrayList([]M31) = .empty,

        /// Whether we should retain coefficients.
        retain_coefficients: bool,
        compact_committer: ?CompactCommitter = null,
        compact_column_count: usize = 0,
        compact_failed: bool = false,
        cached_commitment: ?MerkleProver = null,
        compact_tail_start: ?usize = null,
        compact_tail_refs: std.ArrayList(MerkleProver.ColumnRef) = .empty,

        const Self = @This();
        const CompactHasher = if (H == @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher)
            @import("../vcs_lifted/compact_blake3_leaf.zig").Hasher
        else
            H;
        const b2 = @import("stwo_core").vcs_lifted.blake2_merkle;
        const compact_blake2 = H == b2.Blake2sMerkleHasher or H == b2.Blake2sM31MerkleHasher or
            H == b2.Blake2sPlainMerkleHasher or H == b2.Blake2sPlainM31MerkleHasher;
        const compact_supported = compact_blake2 or H == @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher;
        const compact_max_columns = if (compact_blake2) std.math.maxInt(usize) else if (@hasDecl(CompactHasher, "max_columns")) CompactHasher.max_columns else 0;
        const native_compact = if (@hasDecl(B, "supportsCompactStreaming")) B.supportsCompactStreaming(H) else false;
        const CompactCommitter = if (native_compact) B.CompactStreamingCommitter(H) else @import("../vcs_lifted/streaming_committer.zig").StreamingCommitter(CompactHasher, MerkleProver);

        pub fn init(
            allocator: std.mem.Allocator,
            scheme: *Scheme,
            batch_size: usize,
        ) Self {
            return .{
                .allocator = allocator,
                .commitment_scheme = scheme,
                .batch_size = if (batch_size == 0) 64 else batch_size,
                .streaming_committer = MerkleProver.StreamingCommitter.init(allocator),
                .retained_columns = std.ArrayList(ColumnEvaluation).empty,
                .retained_column_allocator = scheme.retained_column_allocator,
                .retained_column_indices = std.ArrayList(usize).empty,
                .retained_coefficients = std.ArrayList(prover_circle.CircleCoefficients).empty,
                .retain_coefficients = scheme.coefficient_retention_policy == .always,
                .compact_committer = if (compact_supported and
                    (B.MerkleTree(H) == MerkleProver or native_compact) and scheme.compact_polynomial_storage)
                    CompactCommitter.init(allocator)
                else
                    null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.streaming_committer.deinit();
            for (self.compact_tail_refs.items) |reference| self.allocator.free(reference.values);
            self.compact_tail_refs.deinit(self.allocator);
            if (self.cached_commitment) |*tree| tree.deinit(self.allocator);
            if (self.compact_committer) |*committer| committer.deinit();
            if (self.retained_column_backings.items.len > 0) {
                for (self.retained_column_backings.items) |backing| backing.deinit(self.allocator);
            } else for (self.retained_columns.items) |col| {
                if (col.values.len > 0) (self.retained_column_allocator orelse self.allocator).free(col.values);
            }
            self.retained_column_backings.deinit(self.allocator);
            self.retained_columns.deinit(self.allocator);
            self.retained_column_indices.deinit(self.allocator);
            for (self.retained_coefficients.items) |*coeff| {
                var c = coeff.*;
                c.deinit(self.allocator);
            }
            self.retained_coefficients.deinit(self.allocator);
            for (self.retained_coefficient_buffers.items) |buffer| self.allocator.free(buffer);
            self.retained_coefficient_buffers.deinit(self.allocator);
            self.* = undefined;
        }

        /// Only an explicitly armed, protocol-bound fixed-data source may
        /// bypass hashing. Admit from the complete sorted domain shape before
        /// any LDE batch is retired, using the same checked cache as ordinary PCS.
        pub fn planCompactTree(self: *Self, columns: []const ColumnEvaluation, order: []const usize) !void {
            if (self.compact_committer == null) return;
            if (comptime @hasDecl(CompactCommitter, "planColumnCount"))
                try self.compact_committer.?.planColumnCount(order.len);
            const refs = try self.allocator.alloc(MerkleProver.ColumnRef, order.len);
            defer self.allocator.free(refs);
            for (order, refs, 0..) |index, *reference, i| reference.* = .{
                .log_size = std.math.add(u32, columns[index].log_size, self.commitment_scheme.config.fri_config.log_blowup_factor) catch return error.InvalidColumnLogSize,
                .values = &.{},
                .original_index = i,
            };
            self.compact_tail_start = CompactCommitter.compactLiftedTailStart(refs);
            if (self.compact_tail_start) |start|
                try self.compact_tail_refs.ensureTotalCapacity(self.allocator, refs.len - start);
            self.cached_commitment = cached_tree.loadSorted(H, self.allocator, refs);
        }

        /// Add a batch of owned columns.  The column values are consumed:
        /// they are interpolated, extended to the commitment domain, retained for
        /// the Merkle leaf pass, and the *original* values freed.
        /// The *extended* values are retained (needed for decommitment).
        ///
        /// Columns MUST be supplied so that within each call (and across calls)
        /// their extended log_sizes are non-decreasing.  In practice, grouping
        /// columns by their original log_size achieves this.
        pub fn addColumnsOwned(
            self: *Self,
            owned_batch: []ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
        ) !void {
            const first_index = self.retained_column_indices.items.len;
            const indices = self.allocator.alloc(usize, owned_batch.len) catch |err| {
                column_storage.freeOwnedColumnEvaluations(self.allocator, owned_batch);
                return err;
            };
            defer self.allocator.free(indices);
            for (indices, 0..) |*index, i| index.* = first_index + i;
            return self.addColumnsOwnedIndexed(owned_batch, indices, recorder);
        }

        fn addColumnsOwnedIndexed(
            self: *Self,
            owned_batch: []ColumnEvaluation,
            original_indices: []const usize,
            recorder: ?*stage_profile.Recorder,
        ) !void {
            return self.addColumnsIndexed(owned_batch, original_indices, recorder, null);
        }

        /// The stream, rather than each batch, retains the shared source arena.
        pub fn addColumnsBorrowingArenaIndexed(self: *Self, owned_batch: []ColumnEvaluation, original_indices: []const usize, recorder: ?*stage_profile.Recorder, arena: []M31) !void {
            return self.addColumnsIndexed(owned_batch, original_indices, recorder, arena);
        }

        fn freeBatch(self: *Self, batch: []ColumnEvaluation, arena: ?[]M31) void {
            if (arena != null) self.allocator.free(batch) else column_storage.freeOwnedColumnEvaluations(self.allocator, batch);
        }

        fn addColumnsIndexed(self: *Self, owned_batch: []ColumnEvaluation, original_indices: []const usize, recorder: ?*stage_profile.Recorder, arena: ?[]M31) !void {
            std.debug.assert(owned_batch.len == original_indices.len);
            if (self.compact_failed) {
                self.freeBatch(owned_batch, arena);
                return error.IncrementalCommitmentFailed;
            }
            errdefer if (self.compact_committer != null) {
                self.compact_failed = true;
            };
            if (owned_batch.len == 0) {
                self.allocator.free(owned_batch);
                return;
            }

            if (self.retained_column_allocator != null and
                (self.commitment_scheme.coefficient_retention_policy != .never or owned_batch.len > 64))
            {
                self.freeBatch(owned_batch, arena);
                return error.UnsupportedRetainedColumnStorage;
            }

            const log_blowup = self.commitment_scheme.config.fri_config.log_blowup_factor;

            // Determine coefficient retention for this batch.
            const batch_retain = self.retain_coefficients or
                column_storage.shouldRetainCoefficients(owned_batch, self.commitment_scheme.coefficient_retention_policy);

            // Prepare: interpolate + extend.
            // Follow the same ownership convention as commitOwnedWithRecorder:
            // on error from prepareColumnsForCommitOwned the caller cleans up
            // the input; on success the result owns the data.
            var prepared = (if (arena) |source| column_preparation.prepareColumnsBorrowingArenaForBackend(
                B,
                self.allocator,
                owned_batch,
                log_blowup,
                &self.commitment_scheme.twiddle_source,
                recorder,
                source,
            ) else column_preparation.prepareColumnsForCommitOwnedForBackend(
                B,
                self.allocator,
                owned_batch,
                log_blowup,
                if (batch_retain) CoefficientRetentionPolicy.always else CoefficientRetentionPolicy.never,
                &self.commitment_scheme.twiddle_source,
                recorder,
                null,
            )) catch |err| {
                self.freeBatch(owned_batch, arena);
                return err;
            };
            errdefer prepared.deinit(self.allocator);

            if (self.compact_committer) |*committer| {
                if (prepared.columns.len > compact_max_columns - self.compact_column_count)
                    return error.CompactMerkleLeafTooWide;
                const references = try self.allocator.alloc(MerkleProver.ColumnRef, prepared.columns.len);
                defer self.allocator.free(references);
                for (prepared.columns, references, 0..) |column, *reference, index| reference.* = .{
                    .log_size = column.log_size,
                    .values = column.values,
                    .original_index = index,
                };
                // The public streaming API requires ascending domain sizes.
                for (references, 0..) |reference, index| {
                    if ((index != 0 and reference.log_size < references[index - 1].log_size) or
                        (committer.initialized and reference.log_size < committer.leaf_log_size))
                        return error.InvalidColumnSize;
                }
                if (self.cached_commitment == null) {
                    const prefix_len = if (self.compact_tail_start) |start|
                        @min(references.len, start -| self.compact_column_count)
                    else
                        references.len;
                    if (comptime native_compact)
                        try committer.addColumnsWithBacking(references[0..prefix_len], prepared.column_backing_buffers)
                    else
                        try committer.addColumns(references[0..prefix_len]);
                    for (references[prefix_len..]) |reference| {
                        var tail = reference;
                        tail.values = try self.allocator.dupe(M31, reference.values);
                        self.compact_tail_refs.appendAssumeCapacity(tail);
                    }
                }
                self.compact_column_count += references.len;
                // Compact the prepared batch immediately, before accepting another.
                // Adopt a dummy host commitment solely to reuse the ownership logic.
                var batch_tree = commitment_tree.CommitmentTreeProver(H){
                    .columns = prepared.columns,
                    .coefficients = prepared.coefficients,
                    .column_backing_buffers = prepared.column_backing_buffers,
                    .coefficient_backing_buffers = prepared.coefficient_backing_buffers,
                    .column_backing_alignment = prepared.column_backing_alignment,
                    .commitment = .{ .layers = &.{}, .layer_allocator = self.allocator },
                };
                try batch_tree.compactPolynomialStorage(self.allocator, self.commitment_scheme.compact_polynomial_min_log_size);
                prepared.columns = batch_tree.columns;
                prepared.column_backing_buffers = batch_tree.column_backing_buffers;
                prepared.coefficients = batch_tree.coefficients;
                prepared.coefficient_backing_buffers = batch_tree.coefficient_backing_buffers;
            }

            // Retain preparation layout through openings. Explicit retained
            // storage still relocates independent LDE allocations.
            const preserve_lde = self.compact_committer == null and self.retained_column_allocator == null and
                !std.process.hasEnvVarConstant("STWO_ZIG_DETACH_STREAMING_LDE");
            if (arena == null and std.process.hasEnvVarConstant("STWO_ZIG_DETACH_STREAMING_COEFFICIENTS"))
                try prepared.detachBacking(self.allocator)
            else if (!preserve_lde)
                try prepared.detachColumnBacking(self.allocator);

            if (self.retained_column_allocator != null and
                (prepared.column_backing_buffers != null or prepared.coefficients != null))
                return error.UnsupportedRetainedColumnStorage;

            // Pre-allocate space in retained lists before any ownership transfer.
            try self.retained_columns.ensureUnusedCapacity(self.allocator, prepared.columns.len);
            try self.retained_column_indices.ensureUnusedCapacity(self.allocator, prepared.columns.len);
            if (prepared.coefficients) |coeffs| {
                try self.retained_coefficients.ensureUnusedCapacity(self.allocator, coeffs.len);
            }
            if (prepared.coefficient_backing_buffers) |buffers|
                try self.retained_coefficient_buffers.ensureUnusedCapacity(self.allocator, buffers.len);
            if (preserve_lde) try self.retained_column_backings.ensureUnusedCapacity(
                self.allocator,
                if (prepared.column_backing_buffers) |buffers| buffers.len else prepared.columns.len,
            );

            if (self.retained_column_allocator) |retained_allocator| {
                const original = prepared.columns;
                prepared.columns = &.{};
                prepared.columns = try commitment_tree.relocateOwnedColumns(self.allocator, retained_allocator, original);
            }

            // From here, all operations are guaranteed not to fail (no try).
            if (preserve_lde) {
                if (prepared.column_backing_buffers) |buffers| {
                    for (buffers) |buffer| self.retained_column_backings.appendAssumeCapacity(.{
                        .values = buffer,
                        .alignment = prepared.column_backing_alignment,
                    });
                    self.allocator.free(buffers);
                } else for (prepared.columns) |column| self.retained_column_backings.appendAssumeCapacity(.{
                    .values = @constCast(column.values),
                    .alignment = .of(M31),
                });
            }
            // Retain extended columns (needed for decommitment and quotient evaluation).
            for (prepared.columns, original_indices) |col, original_index| {
                self.retained_columns.appendAssumeCapacity(col);
                self.retained_column_indices.appendAssumeCapacity(original_index);
            }

            // Retain coefficients if needed.
            if (prepared.coefficients) |coeffs| {
                for (coeffs) |coeff| {
                    self.retained_coefficients.appendAssumeCapacity(coeff);
                }
                self.allocator.free(coeffs);
            }

            if (prepared.coefficient_backing_buffers) |buffers| {
                self.retained_coefficient_buffers.appendSliceAssumeCapacity(buffers);
                self.allocator.free(buffers);
            }

            // The prepared.columns outer slice was consumed into retained_columns
            // element-by-element.  Free only the outer allocation.
            self.allocator.free(prepared.columns);
        }

        fn loadCachedTree(self: *Self, sorted: []const MerkleProver.ColumnRef) ?MerkleProver {
            return cached_tree.loadSorted(H, self.allocator, sorted);
        }

        fn storeCachedTree(self: *Self, sorted: []const MerkleProver.ColumnRef, tree: MerkleProver) void {
            cached_tree.storeSorted(H, self.allocator, sorted, tree);
        }

        /// Finalize the streaming commitment: build the full Merkle tree from
        /// the accumulated leaf hashes, create a `CommitmentTreeProver`, mix
        /// the root into the channel, and append the tree to the commitment
        /// scheme.
        pub fn commit(self: *Self, channel: anytype) !void {
            return self.commitWithRecorder(null, channel);
        }

        pub fn commitWithRecorder(
            self: *Self,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            const work_recorder = if (recorder) |active|
                active.workCaptureRecorder()
            else
                null;
            if (self.compact_failed) return error.IncrementalCommitmentFailed;
            const incremental = self.compact_committer != null;
            const leaf_count: usize = if (self.retained_columns.items.len != 0)
                @as(usize, 1) << @intCast(self.retained_columns.items[self.retained_columns.items.len - 1].log_size)
            else
                1;
            var built_complete_tree = true;
            var merkle = if (self.compact_committer) |*committer| blk: {
                if (self.cached_commitment) |cached| {
                    self.cached_commitment = null;
                    committer.deinit();
                    self.compact_committer = null;
                    built_complete_tree = false;
                    break :blk cached;
                }
                const result = if (self.compact_tail_refs.items.len != 0)
                    try committer.finalizeLiftedTail(self.compact_tail_refs.items)
                else
                    try committer.finalize();
                self.compact_committer = null;
                // Column values are retired; domain shape is sufficient for the
                // armed source's cache key. It receives freshly computed hashes.
                const refs = self.allocator.alloc(MerkleProver.ColumnRef, self.retained_columns.items.len) catch null;
                if (refs) |references| {
                    defer self.allocator.free(references);
                    for (self.retained_columns.items, references, 0..) |column, *reference, i| reference.* = .{
                        .log_size = column.log_size,
                        .values = &.{},
                        .original_index = i,
                    };
                    cached_tree.storeSorted(H, self.allocator, references, result);
                }
                break :blk result;
            } else legacy: {
                const col_refs = try self.allocator.alloc([]const M31, self.retained_columns.items.len);
                defer self.allocator.free(col_refs);
                for (self.retained_columns.items, col_refs) |column, *reference| {
                    reference.* = column.values;
                }
                const sorted = try MerkleProver.sortColumnsByLogSizeAsc(self.allocator, col_refs);
                defer self.allocator.free(sorted);
                emitColumnHistogram(H, sorted);

                // An armed layer source may supply the tree outright. Its bytes flow
                // into exactly the pipeline a built tree would, so a wrong load can
                // only produce a transcript the verifier rejects.
                const loaded = self.loadCachedTree(sorted);

                // BLAKE2s' domain-prefixed state can finalize its compact lifted
                // tail directly. Other suites use a bounded native-height prefix:
                // this preserves the old path's critical prefix reuse without
                // retaining a full-domain hasher array. For Poseidon2 at log 21,
                // the explicit 96 MiB cap selects log 20 (72 MiB of state), then
                // writes the 64 MiB final leaf layer directly. The prior full-state
                // path peaked at 208 MiB during this phase; a purely row-batched
                // fallback was smaller but replayed lower-height prefixes and was
                // measured at roughly 10x end-to-end on the real proof workload.
                const supports_sparse_tail = comptime blk: {
                    if (!@hasDecl(H, "domainPrefixBytes")) break :blk false;
                    break :blk H.domainPrefixBytes() == 64;
                };
                var bounded_stats: MerkleProver.BoundedPrefixStats = .{};
                const device_tree = if (comptime @hasDecl(B, "tryCommitStreamingMerkle")) blk: {
                    break :blk if (loaded == null) try B.tryCommitStreamingMerkle(H, self.allocator, col_refs) else null;
                } else null;
                const legacy_merkle = loaded orelse device_tree orelse if (supports_sparse_tail)
                    try self.streaming_committer.commitColumnsWithSparseTail(sorted)
                else if (self.commitment_scheme.reuse_bounded_merkle_tail and
                    !std.process.hasEnvVarConstant("STWO_ZIG_REPLAY_BOUNDED_MERKLE_TAIL"))
                    try self.streaming_committer.commitColumnsWithReusedBoundedPrefix(
                        sorted,
                        bounded_prefix_state_budget_bytes,
                        &bounded_stats,
                    )
                else
                    try self.streaming_committer.commitColumnsWithBoundedPrefix(
                        sorted,
                        bounded_prefix_state_budget_bytes,
                        &bounded_stats,
                    );
                if (loaded == null and device_tree == null and !supports_sparse_tail) {
                    emitBoundedPrefixStats(bounded_stats);
                }
                if (loaded == null) self.storeCachedTree(sorted, legacy_merkle);
                built_complete_tree = loaded == null;
                break :legacy legacy_merkle;
            };
            // Compact only host trees whose query reader can reconstruct leaves.
            // Device adoption retains its existing full-layer contract.
            if (comptime B.MerkleTree(H) == MerkleProver) merkle.compactForQueries();
            // streaming_committer is now consumed; reinitialize to safe state for deinit.
            self.streaming_committer = MerkleProver.StreamingCommitter.init(self.allocator);
            for (self.compact_tail_refs.items) |reference| self.allocator.free(reference.values);
            self.compact_tail_refs.deinit(self.allocator);
            self.compact_tail_refs = .empty;
            errdefer merkle.deinit(self.allocator);

            const original_indices = try self.retained_column_indices.toOwnedSlice(self.allocator);
            self.retained_column_indices = std.ArrayList(usize).empty;
            defer self.allocator.free(original_indices);

            // Backing allocations remain with the builder until final transfer.
            const backed_columns = self.retained_column_backings.items.len > 0;
            // Assemble the retained columns and coefficients into original PCS order.
            const columns = blk: {
                const streamed = try self.retained_columns.toOwnedSlice(self.allocator);
                self.retained_columns = std.ArrayList(ColumnEvaluation).empty;
                errdefer if (backed_columns) self.allocator.free(streamed) else commitment_tree.freeRetainedColumns(self.allocator, self.retained_column_allocator orelse self.allocator, streamed);

                const ordered = try self.allocator.alloc(ColumnEvaluation, streamed.len);
                for (streamed, original_indices) |column, original_index| {
                    ordered[original_index] = column;
                }
                self.allocator.free(streamed);
                break :blk ordered;
            };
            errdefer if (backed_columns) self.allocator.free(columns) else commitment_tree.freeRetainedColumns(self.allocator, self.retained_column_allocator orelse self.allocator, columns);

            var coefficients: ?[]prover_circle.CircleCoefficients = null;
            errdefer if (coefficients) |owned| column_storage.deinitOwnedCoefficientColumns(self.allocator, owned);
            if (self.retained_coefficients.items.len > 0) {
                const streamed_coefficients = try self.retained_coefficients.toOwnedSlice(self.allocator);
                self.retained_coefficients = std.ArrayList(prover_circle.CircleCoefficients).empty;
                errdefer column_storage.deinitOwnedCoefficientColumns(self.allocator, streamed_coefficients);
                if (streamed_coefficients.len == columns.len) {
                    const ordered_coefficients = try self.allocator.alloc(
                        prover_circle.CircleCoefficients,
                        streamed_coefficients.len,
                    );
                    for (streamed_coefficients, original_indices) |coefficient, original_index| {
                        ordered_coefficients[original_index] = coefficient;
                    }
                    self.allocator.free(streamed_coefficients);
                    coefficients = ordered_coefficients;
                } else {
                    coefficients = streamed_coefficients;
                }
            }

            const coefficient_buffers: ?[][]M31 = if (self.retained_coefficient_buffers.items.len > 0)
                try self.retained_coefficient_buffers.toOwnedSlice(self.allocator)
            else
                null;
            errdefer if (coefficient_buffers) |buffers| {
                for (buffers) |buffer| self.allocator.free(buffer);
                self.allocator.free(buffers);
            };
            const column_backings: ?[]commitment_tree.ColumnBacking = if (backed_columns)
                try self.retained_column_backings.toOwnedSlice(self.allocator)
            else
                null;
            errdefer if (column_backings) |backings| {
                for (backings) |backing| backing.deinit(self.allocator);
                self.allocator.free(backings);
            };
            const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);
            const tree = BackendCommitmentTree{
                .columns = columns,
                .retained_column_allocator = self.retained_column_allocator,
                .coefficient_backing_buffers = coefficient_buffers,
                .streaming_column_backings = column_backings,
                .coefficients = coefficients,
                .compact_polynomials = incremental,
                .commitment = if (native_compact and incremental) B.adoptNativeStreamingMerkle(H, merkle) else try adoptStreamingCommitment(B, H, merkle),
            };
            try appendCommittedTree(MC, self.commitment_scheme, self.allocator, tree, channel);
            recordStreamingMerkleWork(work_recorder, built_complete_tree, leaf_count);
        }
    };
}

fn recordStreamingMerkleWork(
    recorder: ?*work_profile.Recorder(true),
    built_complete_tree: bool,
    leaf_count: usize,
) void {
    const active = recorder orelse return;
    if (!built_complete_tree) {
        active.markIncomplete();
        return;
    }
    const encoded_leaf_count = std.math.cast(u64, leaf_count) orelse
        return active.markIncomplete();
    const compression_count = work_profile.logicalMerkleCompressions(
        encoded_leaf_count,
        false,
    ) catch return active.markIncomplete();
    active.recordCompletedDelta(.{
        .site = .streaming_commitment_merkle,
        .producer = .streaming_commitment_merkle,
        .source_mask = work_profile.SourceMask.one(.merkle_compressions),
        .counters = .{ .merkle_compressions = compression_count },
    }) catch active.markIncomplete();
    // work-profile-complete:streaming-commitment-merkle
}

test "streaming Merkle work records every completed internal node at its exact site" {
    var recorder: work_profile.Recorder(true) = .{};

    recordStreamingMerkleWork(&recorder, true, 8);

    try std.testing.expectEqual(@as(u64, 7), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.streaming_commitment_merkle)],
    );
    try std.testing.expect(!recorder.legacy_site_coverage);
    try std.testing.expect(!recorder.incomplete);
}

test "streaming Merkle work records an exercised one-leaf tree as exact zero" {
    var recorder: work_profile.Recorder(true) = .{};

    recordStreamingMerkleWork(&recorder, true, 1);

    try std.testing.expectEqual(@as(u64, 0), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expect(recorder.source_mask.contains(.merkle_compressions));
    try std.testing.expect(!recorder.incomplete);
}

test "streaming Merkle work fails closed for cache-loaded trees" {
    var recorder: work_profile.Recorder(true) = .{};

    recordStreamingMerkleWork(&recorder, false, 8);

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
    try std.testing.expectEqual(
        work_profile.Authority.unavailable,
        (try recorder.snapshot()).authority,
    );
}

test "streaming Merkle work fails closed for a non-binary leaf shape" {
    var recorder: work_profile.Recorder(true) = .{};

    recordStreamingMerkleWork(&recorder, true, 3);

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
}
