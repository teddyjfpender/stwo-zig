//! Owned and streaming PCS tree construction.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const prover_circle = @import("../poly/circle/mod.zig");
const stage_profile = @import("../stage_profile.zig");
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");
const commitment_tree = @import("commitment_tree.zig");
const column_preparation = @import("columns/preparation.zig");
const column_storage = @import("columns/storage.zig");

const M31 = m31.M31;
const TreeSubspan = pcs_core.TreeSubspan;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const CoefficientRetentionPolicy = column_storage.CoefficientRetentionPolicy;

const deferred_commit = @import("deferred_commit.zig");
const merkle_layer_cache = @import("merkle_layer_cache.zig");

/// Re-derives every layer at or above `spot_check_limit` nodes from the layer
/// below it. A loaded artifact that passes its own integrity digest can still
/// be internally inconsistent — written by a different revision, or by a
/// truncated writer that produced a well-formed shorter tree — and this catches
/// that class without paying for a full rebuild. It is a availability guard,
/// not a soundness one: an inconsistent tree that slipped through would change
/// the root, and the root is what the transcript commits to.
fn topLayersRederive(comptime H: type, layers: []const []H.Hash) bool {
    const spot_check_limit: usize = 4096;
    if (layers.len < 2) return false;
    var index: usize = 0;
    while (index + 1 < layers.len and layers[index].len <= spot_check_limit) : (index += 1) {
        const parents = layers[index];
        const children = layers[index + 1];
        if (children.len != parents.len * 2) return false;
        for (parents, 0..) |parent, position| {
            const recomputed = H.hashChildren(.{
                .left = children[2 * position],
                .right = children[2 * position + 1],
            });
            if (!std.mem.eql(
                u8,
                std.mem.asBytes(&parent),
                std.mem.asBytes(&recomputed),
            )) return false;
        }
    }
    return index > 0;
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
    try scheme.trees.append(allocator, tree);
    MC.mixRoot(channel, tree.root());
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
            errdefer {
                column_storage.freeOwnedColumnEvaluations(self.allocator, base_columns);
            }

            var prepared = try column_preparation.prepareColumnsForCommitOwnedForBackend(
                B,
                self.allocator,
                base_columns,
                self.commitment_scheme.config.fri_config.log_blowup_factor,
                self.commitment_scheme.coefficient_retention_policy,
                &self.commitment_scheme.twiddle_source,
                null,
            );
            errdefer prepared.deinit(self.allocator);

            var tree = try commitment_tree.CommitmentTreeProverForBackend(B, H).initOwnedWithBacking(
                self.allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
            );
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

        /// Original PCS position for each retained column. Streaming hashes
        /// columns in log-size order, then restores this order before commit.
        retained_column_indices: std.ArrayList(usize),

        /// Coefficient polynomials retained for sampled-value evaluation
        /// (only when the retention policy says to keep them).
        retained_coefficients: std.ArrayList(prover_circle.CircleCoefficients),

        /// Whether we should retain coefficients.
        retain_coefficients: bool,

        const Self = @This();

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
                .retained_column_indices = std.ArrayList(usize).empty,
                .retained_coefficients = std.ArrayList(prover_circle.CircleCoefficients).empty,
                .retain_coefficients = scheme.coefficient_retention_policy == .always,
            };
        }

        pub fn deinit(self: *Self) void {
            self.streaming_committer.deinit();
            for (self.retained_columns.items) |col| {
                if (col.values.len > 0) self.allocator.free(col.values);
            }
            self.retained_columns.deinit(self.allocator);
            self.retained_column_indices.deinit(self.allocator);
            for (self.retained_coefficients.items) |*coeff| {
                var c = coeff.*;
                c.deinit(self.allocator);
            }
            self.retained_coefficients.deinit(self.allocator);
            self.* = undefined;
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
            const indices = try self.allocator.alloc(usize, owned_batch.len);
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
            std.debug.assert(owned_batch.len == original_indices.len);
            if (owned_batch.len == 0) {
                self.allocator.free(owned_batch);
                return;
            }

            const log_blowup = self.commitment_scheme.config.fri_config.log_blowup_factor;

            // Determine coefficient retention for this batch.
            const batch_retain = self.retain_coefficients or
                column_storage.shouldRetainCoefficients(owned_batch, self.commitment_scheme.coefficient_retention_policy);

            // Prepare: interpolate + extend.
            // Follow the same ownership convention as commitOwnedWithRecorder:
            // on error from prepareColumnsForCommitOwned the caller cleans up
            // the input; on success the result owns the data.
            var prepared = column_preparation.prepareColumnsForCommitOwnedForBackend(
                B,
                self.allocator,
                owned_batch,
                log_blowup,
                if (batch_retain) CoefficientRetentionPolicy.always else CoefficientRetentionPolicy.never,
                &self.commitment_scheme.twiddle_source,
                recorder,
            ) catch |err| {
                column_storage.freeOwnedColumnEvaluations(self.allocator, owned_batch);
                return err;
            };
            errdefer prepared.deinit(self.allocator);

            // Pre-allocate space in retained lists before any ownership transfer.
            try self.retained_columns.ensureUnusedCapacity(self.allocator, prepared.columns.len);
            try self.retained_column_indices.ensureUnusedCapacity(self.allocator, prepared.columns.len);
            if (prepared.coefficients) |coeffs| {
                try self.retained_coefficients.ensureUnusedCapacity(self.allocator, coeffs.len);
            }

            // From here, all operations are guaranteed not to fail (no try).
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

            // The prepared.columns outer slice was consumed into retained_columns
            // element-by-element.  Free only the outer allocation.
            self.allocator.free(prepared.columns);
        }

        /// Describes the tree this commit is about to produce, for an armed
        /// layer source. Returns null when nothing is armed or the shape is
        /// outside what an artifact may describe.
        fn cacheRequest(
            sorted: []const MerkleProver.ColumnRef,
            column_log_sizes: []u32,
        ) ?merkle_layer_cache.Request {
            if (sorted.len == 0) return null;
            const log_size = sorted[sorted.len - 1].log_size;
            if (log_size < 1 or log_size > 30) return null;
            for (sorted, column_log_sizes) |column, *entry| entry.* = column.log_size;
            return .{
                .hasher_tag = @typeName(H),
                .hash_bytes = @sizeOf(H.Hash),
                .log_size = log_size,
                .column_log_sizes = column_log_sizes,
            };
        }

        fn loadCachedTree(
            self: *Self,
            sorted: []const MerkleProver.ColumnRef,
        ) ?MerkleProver {
            const source = merkle_layer_cache.armed() orelse return null;
            const column_log_sizes = self.allocator.alloc(u32, sorted.len) catch return null;
            defer self.allocator.free(column_log_sizes);
            const request = cacheRequest(sorted, column_log_sizes) orelse return null;

            const layers = MerkleProver.allocateLayers(
                self.allocator,
                request.log_size,
            ) catch return null;
            var adopted = false;
            defer if (!adopted) MerkleProver.freeLayers(self.allocator, layers);

            const views = self.allocator.alloc([]u8, layers.len) catch return null;
            defer self.allocator.free(views);
            for (layers, views) |layer, *view| view.* = std.mem.sliceAsBytes(layer);

            if (!source.load(source.ctx, request, views)) return null;
            if (!topLayersRederive(H, layers)) return null;
            adopted = true;
            return MerkleProver.fromLayers(self.allocator, layers);
        }

        fn storeCachedTree(
            self: *Self,
            sorted: []const MerkleProver.ColumnRef,
            merkle: MerkleProver,
        ) void {
            const source = merkle_layer_cache.armed() orelse return;
            const column_log_sizes = self.allocator.alloc(u32, sorted.len) catch return;
            defer self.allocator.free(column_log_sizes);
            const request = cacheRequest(sorted, column_log_sizes) orelse return;
            if (merkle.layers.len != @as(usize, request.log_size) + 1) return;

            const views = self.allocator.alloc([]const u8, merkle.layers.len) catch return;
            defer self.allocator.free(views);
            for (merkle.layers, views) |layer, *view| view.* = std.mem.sliceAsBytes(layer);
            source.store(source.ctx, request, views);
        }

        /// Finalize the streaming commitment: build the full Merkle tree from
        /// the accumulated leaf hashes, create a `CommitmentTreeProver`, mix
        /// the root into the channel, and append the tree to the commitment
        /// scheme.
        pub fn commit(self: *Self, channel: anytype) !void {
            const col_refs = try self.allocator.alloc([]const M31, self.retained_columns.items.len);
            defer self.allocator.free(col_refs);
            for (self.retained_columns.items, col_refs) |column, *reference| {
                reference.* = column.values;
            }
            const sorted = try MerkleProver.sortColumnsByLogSizeAsc(self.allocator, col_refs);
            defer self.allocator.free(sorted);

            // An armed layer source may supply the tree outright. Its bytes flow
            // into exactly the pipeline a built tree would, so a wrong load can
            // only produce a transcript the verifier rejects.
            const loaded = self.loadCachedTree(sorted);

            // Preserve incremental lifted hashing for the dense prefix, while
            // allowing the committer to bypass sparse high-domain expansions.
            var merkle = loaded orelse
                try self.streaming_committer.commitColumnsWithSparseTail(sorted);
            if (loaded == null) self.storeCachedTree(sorted, merkle);
            // streaming_committer is now consumed; reinitialize to safe state for deinit.
            self.streaming_committer = MerkleProver.StreamingCommitter.init(self.allocator);
            errdefer merkle.deinit(self.allocator);

            const original_indices = try self.retained_column_indices.toOwnedSlice(self.allocator);
            self.retained_column_indices = std.ArrayList(usize).empty;
            defer self.allocator.free(original_indices);

            // Assemble the retained columns and coefficients into original PCS order.
            const columns = blk: {
                const streamed = try self.retained_columns.toOwnedSlice(self.allocator);
                self.retained_columns = std.ArrayList(ColumnEvaluation).empty;
                errdefer column_storage.freeOwnedColumnEvaluations(self.allocator, streamed);

                const ordered = try self.allocator.alloc(ColumnEvaluation, streamed.len);
                for (streamed, original_indices) |column, original_index| {
                    ordered[original_index] = column;
                }
                self.allocator.free(streamed);
                break :blk ordered;
            };
            errdefer column_storage.freeOwnedColumnEvaluations(self.allocator, columns);

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

            const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);
            const tree = BackendCommitmentTree{
                .columns = columns,
                .coefficients = coefficients,
                .commitment = try adoptStreamingCommitment(B, H, merkle),
            };
            try appendCommittedTree(MC, self.commitment_scheme, self.allocator, tree, channel);
        }
    };
}
