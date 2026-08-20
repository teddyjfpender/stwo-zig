const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const lifted_merkle_hasher = @import("stwo_core").vcs_lifted.merkle_hasher;
const work_pool_mod = @import("../work_pool.zig");
const quotient_ops = @import("../pcs/quotient_ops.zig");
const quotient_tile_sink = @import("../pcs/quotient_tile_sink.zig");
const secure_column = @import("../secure_column.zig");
const decommit_mod = @import("decommit.zig");
const columns_mod = @import("columns.zig");
const first_layer_sink = @import("first_layer_sink.zig");
const leaves_mod = @import("leaves.zig");
const expand_mod = @import("expand.zig");
const layers_mod = @import("layers.zig");
const parameters = @import("parameters.zig");
const streaming_committer = @import("streaming_committer.zig");

const M31 = m31.M31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub fn MerkleProverLifted(comptime H: type) type {
    comptime lifted_merkle_hasher.assertMerkleHasherLifted(H);
    return struct {
        /// Merkle layers from root to largest layer.
        layers: [][]H.Hash,
        /// Allocator used for individual layer data buffers. When mmap is
        /// available and layers are large enough, this is MmapAllocator
        /// (MADV_SEQUENTIAL hint for streaming hash reads). The outer
        /// `layers` array itself is always freed with the caller's allocator.
        layer_allocator: std.mem.Allocator,

        const Self = @This();
        const LeafOps = leaves_mod.Operations(H);
        const ExpandOps = expand_mod.Operations(H);
        const LayerOps = layers_mod.Operations(H);
        const LayerExecutor = LayerOps.Executor;
        const parallel_min_nodes_per_worker = parameters.parallel_min_nodes_per_worker;
        const default_leaf_batch_size = parameters.default_leaf_batch_size;
        const batched_leaf_threshold = parameters.batched_leaf_threshold;
        const layerAllocator = parameters.layerAllocator;
        const merkleWorkerOverride = parameters.merkleWorkerOverride;
        const leafBatchSizeOverride = parameters.leafBatchSizeOverride;
        const merklePoolReuseEnabled = parameters.merklePoolReuseEnabled;
        const WaitGroup = std.Thread.WaitGroup;

        pub const DecommitmentResult = decommit_mod.DecommitmentResult(H);
        pub const LazyQuotientCommitStats = quotient_tile_sink.ExecutionStats;
        pub const LazyQuotientCommitMode = enum { tiled, legacy };

        /// Exact allocation and replay ledger for bounded-prefix leaf
        /// construction. `leaf_phase_peak_bytes` counts the retained prefix
        /// states and the final leaf layer; column storage and the permanent
        /// upper Merkle layers are deliberately outside this leaf-builder
        /// metric.
        pub const BoundedPrefixStats = struct {
            final_log_size: u32 = 0,
            prefix_log_size: u32 = 0,
            prefix_column_count: usize = 0,
            tail_column_count: usize = 0,
            prefix_state_count: usize = 0,
            prefix_state_bytes: usize = 0,
            leaf_layer_bytes: usize = 0,
            leaf_phase_peak_bytes: usize = 0,
            tail_absorptions: usize = 0,
            repeated_tail_absorptions: usize = 0,
        };

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.layers) |layer| self.layer_allocator.free(layer);
            allocator.free(self.layers);
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return self.layers[0][0];
        }

        /// Allocates an empty layer set shaped for `log_size` (root first,
        /// `layers[i].len == 1 << i`) using exactly the storage discipline
        /// `commit` would have used, so the result can be adopted by
        /// `fromLayers` and released by the ordinary `deinit`.
        pub fn allocateLayers(
            allocator: std.mem.Allocator,
            log_size: u32,
        ) ![][]H.Hash {
            const layer_alloc = layerAllocator(allocator);
            const layers = try allocator.alloc([]H.Hash, @as(usize, log_size) + 1);
            var filled: usize = 0;
            errdefer {
                for (layers[0..filled]) |layer| layer_alloc.free(layer);
                allocator.free(layers);
            }
            while (filled < layers.len) : (filled += 1) {
                layers[filled] = try layer_alloc.alloc(
                    H.Hash,
                    @as(usize, 1) << @intCast(filled),
                );
            }
            return layers;
        }

        pub fn freeLayers(allocator: std.mem.Allocator, layers: [][]H.Hash) void {
            const layer_alloc = layerAllocator(allocator);
            for (layers) |layer| layer_alloc.free(layer);
            allocator.free(layers);
        }

        /// Adopts an externally supplied layer set. The caller is responsible
        /// for having established that the layers are the ones this tree would
        /// have built; the transcript fails closed otherwise.
        pub fn fromLayers(allocator: std.mem.Allocator, layers: [][]H.Hash) Self {
            return .{ .layers = layers, .layer_allocator = layerAllocator(allocator) };
        }

        pub fn commit(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            return commitWithOptions(
                allocator,
                columns,
                merkleWorkerOverride(allocator),
                reuseAvailablePool(allocator),
            );
        }

        /// Builds a Merkle tree by computing quotient values lazily from the
        /// provider, chunk by chunk.  Simultaneously writes the computed
        /// quotient coordinates into `out_column`, so the caller obtains both
        /// the Merkle commitment and the materialized column without ever
        /// needing a separate full-column allocation before hashing.
        pub fn commitWithLazyQuotients(
            allocator: std.mem.Allocator,
            provider: *quotient_ops.LazyQuotientProvider,
            out_column: *SecureColumnByCoords,
        ) !Self {
            var stats: LazyQuotientCommitStats = undefined;
            return commitWithLazyQuotientsMode(
                allocator,
                provider,
                out_column,
                .tiled,
                &stats,
            );
        }

        pub fn commitWithLazyQuotientsLegacy(
            allocator: std.mem.Allocator,
            provider: *quotient_ops.LazyQuotientProvider,
            out_column: *SecureColumnByCoords,
        ) !Self {
            var stats: LazyQuotientCommitStats = undefined;
            return commitWithLazyQuotientsMode(
                allocator,
                provider,
                out_column,
                .legacy,
                &stats,
            );
        }

        pub fn commitWithLazyQuotientsMode(
            allocator: std.mem.Allocator,
            provider: *quotient_ops.LazyQuotientProvider,
            out_column: *SecureColumnByCoords,
            mode: LazyQuotientCommitMode,
            stats: *LazyQuotientCommitStats,
        ) !Self {
            const domain_size = provider.domain_size;
            if (domain_size < 2 or !std.math.isPowerOfTwo(domain_size)) return error.InvalidColumnSize;
            const log_size: u32 = @intCast(std.math.log2_int(usize, domain_size));
            const layer_alloc = layerAllocator(allocator);

            const leaves = switch (mode) {
                .tiled => blk: {
                    var sink = try first_layer_sink.FirstLayerLeafSink(H).init(
                        layer_alloc,
                        domain_size,
                    );
                    defer sink.deinit();
                    stats.* = try provider.computeAllWithTileSink(
                        allocator,
                        out_column,
                        sink.factory(),
                    );
                    break :blk try sink.takeLeaves();
                },
                .legacy => blk: {
                    try provider.computeAll(allocator, out_column);
                    const owned_leaves = try layer_alloc.alloc(H.Hash, domain_size);
                    errdefer layer_alloc.free(owned_leaves);
                    hashLazyQuotientLeaves(out_column, owned_leaves);
                    stats.* = .{
                        .tile_pipeline_selected = false,
                        .worker_count = 0,
                        .tile_row_limit = 0,
                        .tile_count = 0,
                        .peak_scratch_bytes_per_worker = 0,
                        .total_scratch_bytes = 0,
                        .bounded_numerator_tile_bytes_per_worker = 0,
                        .complete_column_combined_intermediate_bytes = try provider.combinedIntermediateBytes(),
                        .post_compute_leaf_pass_count = 1,
                    };
                    break :blk owned_leaves;
                },
            };
            return buildTreeFromOwnedLeaves(allocator, layer_alloc, leaves, log_size);
        }

        fn buildTreeFromOwnedLeaves(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            leaves: []H.Hash,
            log_size: u32,
        ) !Self {
            _ = log_size;
            var leaves_appended = false;
            errdefer if (!leaves_appended) layer_alloc.free(leaves);

            // Build internal Merkle layers from the leaves upward.
            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| layer_alloc.free(layer);
            }

            try layers_bottom_up.ensureUnusedCapacity(allocator, 1);
            layers_bottom_up.appendAssumeCapacity(leaves);
            leaves_appended = true;

            if (leaves.len > 1) {
                const max_out_len = leaves.len >> 1;
                const worker_override = merkleWorkerOverride(allocator);
                var executor: LayerExecutor = undefined;
                executor.init(
                    max_out_len,
                    worker_override,
                    reuseAvailablePool(allocator),
                );
                defer executor.deinit();

                try LayerOps.buildUpperLayersSubtree(
                    allocator,
                    layer_alloc,
                    leaves,
                    &executor,
                    worker_override,
                    &layers_bottom_up,
                );
            }

            const out_layers = try allocator.alloc([]H.Hash, layers_bottom_up.items.len);
            var j: usize = 0;
            while (j < out_layers.len) : (j += 1) {
                out_layers[j] = layers_bottom_up.items[out_layers.len - 1 - j];
            }
            return .{ .layers = out_layers, .layer_allocator = layer_alloc };
        }

        const LazyLeafRange = struct {
            column: *const SecureColumnByCoords,
            leaves: []H.Hash,
            start: usize,
            end: usize,
        };

        fn hashLazyLeafRange(work: *const LazyLeafRange) void {
            var position = work.start;
            if (comptime @hasDecl(H, "leafSeed") and
                @hasDecl(H, "hashDirectM31LeavesWithSeed4"))
            {
                const DirectColumn = struct { values: []const M31 };
                var columns: [qm31.SECURE_EXTENSION_DEGREE]DirectColumn = undefined;
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    columns[coordinate] = .{ .values = work.column.columns[coordinate] };
                }
                const seed = H.leafSeed();
                while (position + 4 <= work.end) : (position += 4) {
                    const hashes = H.hashDirectM31LeavesWithSeed4(seed, &columns, position);
                    inline for (0..4) |lane| work.leaves[position + lane] = hashes[lane];
                }
            }
            while (position < work.end) : (position += 1) {
                var values: [qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
                    values[coord] = work.column.columns[coord][position];
                }
                var hasher = H.defaultWithInitialState();
                hasher.updateLeaf(values[0..]);
                work.leaves[position] = hasher.finalize();
            }
        }

        fn hashLazyQuotientLeaves(column: *const SecureColumnByCoords, leaves: []H.Hash) void {
            const pool = work_pool_mod.getGlobalPool() orelse {
                hashLazyLeafRange(&.{ .column = column, .leaves = leaves, .start = 0, .end = leaves.len });
                return;
            };
            const worker_count = @min(pool.workerCount(), leaves.len / parallel_min_nodes_per_worker);
            if (worker_count <= 1) {
                hashLazyLeafRange(&.{ .column = column, .leaves = leaves, .start = 0, .end = leaves.len });
                return;
            }

            var work: [work_pool_mod.MAX_WORKERS]LazyLeafRange = undefined;
            const chunk_len = (leaves.len + worker_count - 1) / worker_count;
            for (0..worker_count) |worker| {
                const start = worker * chunk_len;
                work[worker] = .{
                    .column = column,
                    .leaves = leaves,
                    .start = start,
                    .end = @min(leaves.len, start + chunk_len),
                };
            }

            var wait_group: WaitGroup = .{};
            for (work[1..worker_count]) |*item| {
                pool.spawnWg(&wait_group, hashLazyLeafRange, .{@as(*const LazyLeafRange, item)});
            }
            hashLazyLeafRange(&work[0]);
            wait_group.wait();
        }

        fn commitWithWorkerOverride(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            worker_override: ?usize,
        ) !Self {
            return commitWithOptions(allocator, columns, worker_override, false);
        }

        fn commitWithOptions(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            worker_override: ?usize,
            reuse_pool: bool,
        ) !Self {
            const sorted = try sortColumnsByLogSizeAsc(allocator, columns);
            defer allocator.free(sorted);

            // Use MmapAllocator for individual layer buffers (sequential-read
            // hint helps the OS prefetcher during Merkle hashing).
            const layer_alloc = layerAllocator(allocator);

            if (allColumnsConstant(sorted)) {
                return commitConstantColumns(allocator, layer_alloc, sorted);
            }

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| layer_alloc.free(layer);
            }

            // Choose leaf-building strategy based on domain size.  For large
            // domains, use the row-batch path to keep the transient hasher
            // array bounded (saves ~(N - batch_size) * sizeof(H) peak RAM,
            // e.g. >100 MiB for 2^20 leaves with Blake2s).
            const leaves = blk: {
                if (sorted.len > 0) {
                    const max_col_log_size = sorted[sorted.len - 1].log_size;
                    const total_leaves = @as(usize, 1) << @intCast(max_col_log_size);
                    if (total_leaves >= batched_leaf_threshold) {
                        const batch_size = leafBatchSizeOverride(allocator) orelse default_leaf_batch_size;
                        break :blk try LeafOps.buildBatched(allocator, layer_alloc, sorted, batch_size);
                    }
                }
                break :blk try LeafOps.build(allocator, layer_alloc, sorted);
            };
            try layers_bottom_up.append(allocator, leaves);

            if (leaves.len > 1) {
                std.debug.assert(std.math.isPowerOfTwo(leaves.len));
                const max_out_len = leaves.len >> 1;
                var executor: LayerExecutor = undefined;
                executor.init(max_out_len, worker_override, reuse_pool);
                defer executor.deinit();

                try LayerOps.buildUpperLayersSubtree(
                    allocator,
                    layer_alloc,
                    leaves,
                    &executor,
                    worker_override,
                    &layers_bottom_up,
                );
            }

            const out_layers = try allocator.alloc([]H.Hash, layers_bottom_up.items.len);
            var i: usize = 0;
            while (i < out_layers.len) : (i += 1) {
                out_layers[i] = layers_bottom_up.items[out_layers.len - 1 - i];
            }
            return .{ .layers = out_layers, .layer_allocator = layer_alloc };
        }

        const allColumnsConstant = columns_mod.allConstant;

        /// Reuse the prover's resident pool whenever one is installed. The
        /// environment switch remains available for standalone Merkle callers
        /// that deliberately opt into the process-level fallback pool.
        fn reuseAvailablePool(allocator: std.mem.Allocator) bool {
            return work_pool_mod.getGlobalPool() != null or merklePoolReuseEnabled(allocator);
        }

        fn commitConstantColumns(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            columns: []const ColumnRef,
        ) !Self {
            const leaf_count = if (columns.len == 0)
                @as(usize, 1)
            else
                @as(usize, 1) << @intCast(columns[columns.len - 1].log_size);

            var leaf_hasher = H.defaultWithInitialState();
            for (columns) |column| leaf_hasher.updateLeaf(column.values[0..1]);
            const leaf_hash = leaf_hasher.finalize();

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer for (layers_bottom_up.items) |layer| layer_alloc.free(layer);

            const leaves = try layer_alloc.alloc(H.Hash, leaf_count);
            @memset(leaves, leaf_hash);
            try layers_bottom_up.append(allocator, leaves);

            var layer_len = leaf_count;
            var child_hash = leaf_hash;
            while (layer_len > 1) {
                layer_len >>= 1;
                child_hash = H.hashChildren(.{ .left = child_hash, .right = child_hash });
                const layer = try layer_alloc.alloc(H.Hash, layer_len);
                @memset(layer, child_hash);
                try layers_bottom_up.append(allocator, layer);
            }

            const out_layers = try allocator.alloc([]H.Hash, layers_bottom_up.items.len);
            for (out_layers, 0..) |*layer, i| {
                layer.* = layers_bottom_up.items[out_layers.len - 1 - i];
            }
            return .{ .layers = out_layers, .layer_allocator = layer_alloc };
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            columns: []const []const M31,
        ) !DecommitmentResult {
            return decommit_mod.decommit(H, self, allocator, query_positions, columns);
        }

        pub fn maxLogSize(self: Self) u32 {
            return @intCast(self.layers.len - 1);
        }

        pub fn readHashes(
            self: Self,
            allocator: std.mem.Allocator,
            layer_log_size: u32,
            indices: []const u32,
        ) ![]H.Hash {
            const layer = self.layers[layer_log_size];
            const out = try allocator.alloc(H.Hash, indices.len);
            for (indices, out) |index, *destination| destination.* = layer[index];
            return out;
        }

        pub const ColumnRef = columns_mod.ColumnRef;
        pub const sortColumnsByLogSizeAsc = columns_mod.sortByLogSizeAsc;

        /// Streaming committer that builds a Merkle tree incrementally from column
        /// batches.  Each batch's column data is consumed and can be freed before
        /// the next batch is fed, reducing peak memory.
        ///
        /// Usage:
        ///   1. `init()` — start a streaming commitment for a known total column set.
        ///   2. `addColumns()` — feed one or more batches of columns (must be
        ///       supplied in ascending log-size order, matching `sortColumnsByLogSizeAsc`).
        ///   3. `finalize()` — finalise the leaf hashes, build the internal tree
        ///       layers, and return the completed `MerkleProverLifted`.
        ///
        /// The resulting Merkle root is bit-identical to calling `commit()` with all
        /// columns at once.
        pub const StreamingCommitter = streaming_committer.StreamingCommitter(H, Self);

        /// `builtin.is_test` keeps structural tests close to their assertions
        /// without making these internals callable from production builds.
        pub const testing = if (builtin.is_test) struct {
            pub fn commitWithWorkerOverride(
                allocator: std.mem.Allocator,
                columns: []const []const M31,
                worker_override: ?usize,
            ) !Self {
                return Self.commitWithWorkerOverride(allocator, columns, worker_override);
            }

            pub fn buildLeaves(
                allocator: std.mem.Allocator,
                layer_alloc: std.mem.Allocator,
                sorted_columns: []const ColumnRef,
            ) ![]H.Hash {
                return LeafOps.build(allocator, layer_alloc, sorted_columns);
            }

            pub fn buildLeavesBatched(
                allocator: std.mem.Allocator,
                layer_alloc: std.mem.Allocator,
                sorted_columns: []const ColumnRef,
                batch_size: usize,
            ) ![]H.Hash {
                return LeafOps.buildBatched(allocator, layer_alloc, sorted_columns, batch_size);
            }

            pub fn buildTreeFromOwnedLeaves(
                allocator: std.mem.Allocator,
                layer_alloc: std.mem.Allocator,
                leaves: []H.Hash,
                log_size: u32,
            ) !Self {
                return Self.buildTreeFromOwnedLeaves(
                    allocator,
                    layer_alloc,
                    leaves,
                    log_size,
                );
            }
        } else struct {};
    };
}
