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
const parents = @import("parents.zig");

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
        const HashExpandOps = expand_mod.Operations(H.Hash);
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
            /// Bounded stack cache storage across active tail workers;
            /// reported separately from the heap-only leaf phase metric.
            tail_cache_bytes: usize = 0,
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
            return allocateLayersPruned(allocator, log_size, 0);
        }

        pub fn allocateLayersPruned(
            allocator: std.mem.Allocator,
            log_size: u32,
            pruned_bottom_layers: u32,
        ) ![][]H.Hash {
            if (pruned_bottom_layers > log_size) return error.InvalidColumnSize;
            const layer_alloc = layerAllocator(allocator);
            const layers = try allocator.alloc([]H.Hash, @as(usize, log_size) + 1);
            var filled: usize = 0;
            errdefer {
                for (layers[0..filled]) |layer| layer_alloc.free(layer);
                allocator.free(layers);
            }
            while (filled < layers.len) : (filled += 1) {
                if (filled > log_size - pruned_bottom_layers) {
                    layers[filled] = &.{};
                    continue;
                }
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

        /// Commits a tree as tall as its largest column (the Native and Cairo
        /// lanes).
        pub fn commit(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            return commitWithOptions(
                allocator,
                columns,
                null,
                merkleWorkerOverride(allocator),
                reuseAvailablePool(allocator),
            );
        }

        /// Commits at an explicit lifting height, as proving@5a7c5ed's
        /// `MerkleProverLifted::commit(columns, lifting_log_size, 0)`: every
        /// column, the largest included, is lifted to `2^lifting_log_size`
        /// leaves. The height must dominate every column and must be 0 when
        /// there are none (an empty tree is one hash of no data). Queries and
        /// decommitments then address the lifted leaves. The lift replicates
        /// the finished leaf layer, so the transient peak is one leaf layer at
        /// the largest column's size plus one at `2^lifting_log_size`.
        /// Bottom-layer pruning (`compactForQueries`) rebuilds leaves at the
        /// largest column's height, so a lifted tree with pruned leaves refuses
        /// to decommit (`error.InvalidColumnSize`) rather than open wrong paths.
        pub fn commitLifted(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            lifting_log_size: u32,
        ) !Self {
            return commitWithOptions(
                allocator,
                columns,
                lifting_log_size,
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

        /// `commitWithLazyQuotients` followed by `compactForQueries`, without
        /// ever holding the layers `compactForQueries` drops. The quotients
        /// are computed into `out_column` first and the provider's quotient
        /// inputs released (`releaseQuotientInputs`: the column is all FRI
        /// reads from here on); then every aligned run of `2^pruned` leaves
        /// is hashed from the column and reduced straight into the lowest
        /// retained layer, and the layers above are hashed from it. Every
        /// leaf and node is the same hash of the same children, so the
        /// retained layers, and the root, are `commitWithLazyQuotients`'s.
        pub fn commitWithLazyQuotientsCompact(
            allocator: std.mem.Allocator,
            provider: *quotient_ops.LazyQuotientProvider,
            out_column: *SecureColumnByCoords,
        ) !Self {
            const domain_size = provider.domain_size;
            if (domain_size < 2 or !std.math.isPowerOfTwo(domain_size)) return error.InvalidColumnSize;
            const log_size: u32 = @intCast(std.math.log2_int(usize, domain_size));
            const pruned = compactPrunedLayers(log_size);
            if (pruned == 0) {
                var tree = try commitWithLazyQuotients(allocator, provider, out_column);
                tree.compactForQueries();
                return tree;
            }

            try provider.computeAll(allocator, out_column);
            provider.releaseQuotientInputs(allocator);

            const layers = try allocateLayersPruned(allocator, log_size, pruned);
            var tree = fromLayers(allocator, layers);
            errdefer tree.deinit(allocator);
            const retained_log = log_size - pruned;
            const retained = tree.layers[retained_log];

            const Job = struct {
                column: *const SecureColumnByCoords,
                /// Retained nodes `[first, first + out.len)`.
                out: []H.Hash,
                first: usize,
                pruned: u32,

                const batch_leaves = 512;

                pub fn run(self: *@This()) void {
                    var ping: [batch_leaves]H.Hash = undefined;
                    var pong: [batch_leaves / 2]H.Hash = undefined;
                    const group = @as(usize, 1) << @intCast(self.pruned);
                    const nodes_per_batch = batch_leaves / group;
                    var done: usize = 0;
                    while (done < self.out.len) {
                        const nodes = @min(nodes_per_batch, self.out.len - done);
                        const leaf_start = (self.first + done) * group;
                        const leaf_count = nodes * group;
                        hashLazyLeafRange(&.{
                            .column = self.column,
                            .leaves = ping[0..leaf_count],
                            .start = leaf_start,
                            .end = leaf_start + leaf_count,
                            .offset = leaf_start,
                        });
                        // Levels below the retained one ping-pong between
                        // the two scratch buffers.
                        var current: []H.Hash = ping[0..leaf_count];
                        var width = leaf_count;
                        var level: u32 = 0;
                        while (level < self.pruned) : (level += 1) {
                            width /= 2;
                            const out = if (level + 1 == self.pruned)
                                self.out[done..][0..width]
                            else if (level % 2 == 0)
                                pong[0..width]
                            else
                                ping[0..width];
                            parents.hashParentsSerial(H, current, out);
                            current = out;
                        }
                        done += nodes;
                    }
                }
            };
            var jobs: [256]Job = undefined;
            const job_count = @min(jobs.len, retained.len);
            const span = retained.len / job_count;
            for (jobs[0..job_count], 0..) |*job, index| job.* = .{
                .column = out_column,
                .out = retained[index * span ..][0..span],
                .first = index * span,
                .pruned = pruned,
            };
            if (work_pool_mod.getGlobalPool()) |pool| {
                var group: WaitGroup = .{};
                for (jobs[1..job_count]) |*job| pool.spawnWg(&group, Job.run, .{job});
                jobs[0].run();
                group.wait();
            } else for (jobs[0..job_count]) |*job| job.run();

            var level = retained_log;
            while (level > 0) : (level -= 1) parents.hashParents(H, tree.layers[level], tree.layers[level - 1]);
            return tree;
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

        /// Consumes already-hashed leaves produced by an admitted backend.
        /// Parent construction and layer ownership remain shared with host proving.
        pub fn fromOwnedLeaves(allocator: std.mem.Allocator, layer_allocator: std.mem.Allocator, leaves: []H.Hash) !Self {
            if (leaves.len == 0 or !std.math.isPowerOfTwo(leaves.len)) {
                layer_allocator.free(leaves);
                return error.InvalidColumnSize;
            }
            return buildTreeFromOwnedLeaves(allocator, layer_allocator, leaves, @intCast(std.math.log2_int(usize, leaves.len)));
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
            /// The row `leaves[0]` holds.
            offset: usize = 0,
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
                    inline for (0..4) |lane| work.leaves[position + lane - work.offset] = hashes[lane];
                }
            }
            while (position < work.end) : (position += 1) {
                var values: [qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
                    values[coord] = work.column.columns[coord][position];
                }
                var hasher = H.defaultWithInitialState();
                hasher.updateLeaf(values[0..]);
                work.leaves[position - work.offset] = hasher.finalize();
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
            return commitWithOptions(allocator, columns, null, worker_override, false);
        }

        /// `lifting_log_size == null` commits at the largest column's height.
        fn commitWithOptions(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            lifting_log_size: ?u32,
            worker_override: ?usize,
            reuse_pool: bool,
        ) !Self {
            const sorted = try sortColumnsByLogSizeAsc(allocator, columns);
            defer allocator.free(sorted);
            const max_col_log_size: u32 = if (sorted.len == 0) 0 else sorted[sorted.len - 1].log_size;
            const height = lifting_log_size orelse max_col_log_size;
            if (height < max_col_log_size or (sorted.len == 0 and height != 0))
                return error.InvalidTreeHeight;

            // Use MmapAllocator for individual layer buffers (sequential-read
            // hint helps the OS prefetcher during Merkle hashing).
            const layer_alloc = layerAllocator(allocator);

            if (allColumnsConstant(sorted)) {
                return commitConstantColumns(allocator, layer_alloc, sorted, height);
            }

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| layer_alloc.free(layer);
            }

            // Four-leaf implementations use the bounded batch path at every
            // size; its scalar tail also handles two-leaf domains. For other
            // hashers, large domains use it to keep the transient hasher
            // array bounded (saves ~(N - batch_size) * sizeof(H) peak RAM,
            // e.g. >100 MiB for 2^20 leaves with Blake2s).
            try layers_bottom_up.ensureUnusedCapacity(allocator, 1);
            const column_leaves = blk: {
                if (sorted.len > 0) {
                    const total_leaves = @as(usize, 1) << @intCast(max_col_log_size);
                    const four_way_leaves = comptime @hasDecl(H, "leafSeed") and @hasDecl(H, "hashPackedLeavesWithSeed4");
                    if (four_way_leaves or total_leaves >= batched_leaf_threshold) {
                        const batch_size = leafBatchSizeOverride(allocator) orelse default_leaf_batch_size;
                        break :blk try LeafOps.buildBatched(allocator, layer_alloc, sorted, batch_size);
                    }
                }
                break :blk try LeafOps.build(allocator, layer_alloc, sorted);
            };
            const leaves = try liftLeaves(layer_alloc, column_leaves, height - max_col_log_size);
            layers_bottom_up.appendAssumeCapacity(leaves);

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

        /// Re-commits a finished tree at a taller explicit height. The result
        /// is the tree `commitLifted(columns, lifting_log_size)` builds from
        /// the same columns: a lifted leaf is the natural leaf at the lifted
        /// index, so only the leaf replication and the node hashes above it
        /// are recomputed, never a column value. This is the single lifting
        /// step behind every commit path of a `proving_5a7c5ed` scheme
        /// (`pcs.revision_lifting`), so no specialised leaf builder needs a
        /// lifted variant. A tree whose leaf layer was pruned
        /// (`compactForQueries`) cannot be lifted and returns
        /// `error.InvalidColumnSize`; a lower height is `InvalidTreeHeight`.
        /// On error the tree is unchanged.
        pub fn liftTo(self: *Self, allocator: std.mem.Allocator, lifting_log_size: u32) !void {
            const natural = self.maxLogSize();
            if (lifting_log_size == natural) return;
            if (lifting_log_size < natural) return error.InvalidTreeHeight;
            const leaves = self.layers[natural];
            if (leaves.len == 0) return error.InvalidColumnSize;
            const layer_alloc = self.layer_allocator;
            const lifted = try liftLeaves(
                layer_alloc,
                try layer_alloc.dupe(H.Hash, leaves),
                lifting_log_size - natural,
            );
            const rebuilt = try buildTreeFromOwnedLeaves(allocator, layer_alloc, lifted, lifting_log_size);
            self.deinit(allocator);
            self.* = rebuilt;
        }

        /// Lifts a finished leaf layer by `log_ratio` more levels:
        /// `lifted[i] = leaves[((i >> (log_ratio + 1)) << 1) + (i & 1)]`, the
        /// final step of upstream `build_leaves`. Takes ownership of `leaves`.
        fn liftLeaves(layer_alloc: std.mem.Allocator, leaves: []H.Hash, log_ratio: u32) ![]H.Hash {
            if (log_ratio == 0) return leaves;
            defer layer_alloc.free(leaves);
            const lifted = try layer_alloc.alloc(H.Hash, leaves.len << @intCast(log_ratio));
            HashExpandOps.expandHashers(lifted, leaves, @intCast(log_ratio + 1));
            return lifted;
        }

        /// Every leaf of a constant-column tree is the same hash at any height.
        fn commitConstantColumns(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            columns: []const ColumnRef,
            height: u32,
        ) !Self {
            const leaf_count = @as(usize, 1) << @intCast(height);

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

        /// Keep the upper tree and reconstruct at most sixteen leaves per
        /// requested lower node. Columns already outlive decommitment; retaining
        /// every leaf digest duplicates gigabytes on large proof domains.
        /// No commitment, transcript or decommitment format changes.
        pub fn compactForQueries(self: *Self) void {
            self.pruneBottomLayers(compactPrunedLayers(self.maxLogSize()));
        }

        /// The bottom layers `compactForQueries` drops from a tree of
        /// `log_size`: none below log 20, else four.
        pub fn compactPrunedLayers(log_size: u32) u32 {
            return if (log_size < 20) 0 else 4;
        }

        pub fn pruneBottomLayers(self: *Self, count: usize) void {
            const first = self.layers.len - @min(count, self.layers.len - 1);
            for (self.layers[first..]) |*layer| {
                self.layer_allocator.free(layer.*);
                layer.* = &.{};
            }
        }

        const QueryReader = @import("query_reconstruction.zig").Reader(H, Self);

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            columns: []const []const M31,
        ) !DecommitmentResult {
            if (self.layers[self.layers.len - 1].len != 0)
                return decommit_mod.decommit(H, self, allocator, query_positions, columns);
            const sorted = try sortColumnsByLogSizeAsc(allocator, columns);
            defer allocator.free(sorted);
            if (sorted.len == 0 or sorted[sorted.len - 1].log_size != self.maxLogSize()) return error.InvalidColumnSize;
            var retained_log_size = self.maxLogSize();
            while (self.layers[retained_log_size].len == 0) retained_log_size -= 1;
            var reader = try QueryReader.init(allocator, self, sorted, retained_log_size, query_positions);
            defer reader.deinit(allocator);
            return decommit_mod.decommit(H, reader, allocator, query_positions, columns);
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
            if (layer_log_size > self.maxLogSize() or self.layers[layer_log_size].len == 0) return error.InvalidColumnSize;
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
            pub fn hashLazyLeafRange(column: *const SecureColumnByCoords, leaves: []H.Hash, start: usize, end: usize) void {
                Self.hashLazyLeafRange(&.{ .column = column, .leaves = leaves, .start = start, .end = end });
            }

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
