//! Streaming lifted-Merkle commitment construction.

const std = @import("std");
const work_pool_mod = @import("../work_pool.zig");
const leaves_mod = @import("leaves.zig");
const expand_mod = @import("expand.zig");
const layers_mod = @import("layers.zig");
const parameters = @import("parameters.zig");

pub fn StreamingCommitter(comptime H: type, comptime Tree: type) type {
    const Self = Tree;
    const ColumnRef = Tree.ColumnRef;
    const BoundedPrefixStats = Tree.BoundedPrefixStats;
    const LeafOps = leaves_mod.Operations(H);
    const ExpandOps = expand_mod.Operations(H);
    const LayerOps = layers_mod.Operations(H);
    const LayerExecutor = LayerOps.Executor;
    const layerAllocator = parameters.layerAllocator;
    const merkleWorkerOverride = parameters.merkleWorkerOverride;
    const merklePoolReuseEnabled = parameters.merklePoolReuseEnabled;
    const WaitGroup = std.Thread.WaitGroup;

    return struct {
        const Committer = @This();

        allocator: std.mem.Allocator,
        /// Leaf hasher state — one hasher per leaf position.
        /// Grows (via expansion) as larger log_size columns are encountered.
        leaf_hashers: []H,
        /// Current log_size of the leaf hasher array (number of positions = 1 << leaf_log_size).
        leaf_log_size: u32,
        /// Whether any columns have been added yet.
        initialized: bool,

        pub fn init(allocator: std.mem.Allocator) Committer {
            return .{
                .allocator = allocator,
                .leaf_hashers = &[_]H{},
                .leaf_log_size = 0,
                .initialized = false,
            };
        }

        pub fn deinit(self: *Committer) void {
            if (self.leaf_hashers.len > 0) {
                self.allocator.free(self.leaf_hashers);
            }
            self.* = undefined;
        }

        /// Feed a batch of columns into the streaming hasher.
        ///
        /// Columns MUST be supplied in ascending log_size order (matching
        /// `sortColumnsByLogSizeAsc` within each batch and across batches).
        /// Columns with the same log_size as columns from a previous batch
        /// are permitted — they extend the same group.
        ///
        /// After this call returns, the caller may free the column value
        /// slices; their data has been absorbed into the leaf hasher state.
        pub fn addColumns(
            self: *Committer,
            columns: []const ColumnRef,
        ) !void {
            if (columns.len == 0) return;

            for (columns) |column| {
                if (!std.math.isPowerOfTwo(column.values.len) or column.values.len < 2) {
                    return error.InvalidColumnSize;
                }
            }

            // Initialize seed hasher on first call.
            if (!self.initialized) {
                const seed_hasher = H.defaultWithInitialState();
                const first_log_size = columns[0].log_size;
                const first_size = @as(usize, 1) << @intCast(first_log_size);
                self.leaf_hashers = try self.allocator.alloc(H, first_size);
                for (self.leaf_hashers) |*h| h.* = seed_hasher;
                self.leaf_log_size = first_log_size;
                self.initialized = true;
            }

            // Process columns in groups by log_size.
            var group_start: usize = 0;
            while (group_start < columns.len) {
                const log_size = columns[group_start].log_size;
                var group_end = group_start + 1;
                while (group_end < columns.len and
                    columns[group_end].log_size == log_size)
                {
                    group_end += 1;
                }

                // Expand leaf hashers if needed for this log_size.
                if (log_size > self.leaf_log_size) {
                    const log_ratio = log_size - self.leaf_log_size;
                    const layer_size = @as(usize, 1) << @intCast(log_size);
                    const shift_amt: std.math.Log2Int(usize) = @intCast(log_ratio + 1);
                    const expanded = try self.allocator.alloc(H, layer_size);
                    ExpandOps.expandHashers(expanded, self.leaf_hashers, shift_amt);
                    self.allocator.free(self.leaf_hashers);
                    self.leaf_hashers = expanded;
                    self.leaf_log_size = log_size;
                }

                const layer_size = self.leaf_hashers.len;
                const group_columns = columns[group_start..group_end];

                // Feed column values into leaf hashers — same kernel as
                // the materialized builder. Generic hashers (including
                // recursion Poseidon2) use disjoint pool-owned ranges;
                // packed BLAKE2s retains its specialized tiled path.
                try LeafOps.updateHashers(
                    self.allocator,
                    self.leaf_hashers,
                    group_columns,
                    layer_size,
                );

                group_start = group_end;
            }
        }

        /// Commits a complete sorted column set while retaining lifted
        /// hasher-state reuse. When the final higher-domain columns fit in
        /// the already-open terminal BLAKE2s block, their intermediate
        /// expanded state arrays are bypassed and finalized directly.
        pub fn commitColumnsWithSparseTail(
            self: *Committer,
            columns: []const ColumnRef,
        ) !Self {
            for (columns, 0..) |column, index| {
                if (!std.math.isPowerOfTwo(column.values.len) or column.values.len < 2) {
                    return error.InvalidColumnSize;
                }
                if (index > 0 and column.log_size < columns[index - 1].log_size) {
                    return error.InvalidColumnOrder;
                }
            }

            const tail_start = liftedTailStart(columns) orelse {
                try self.addColumns(columns);
                return self.finalize();
            };
            try self.addColumns(columns[0..tail_start]);
            return self.finalizeLiftedTail(columns[tail_start..]);
        }

        const BoundedTailRange = struct {
            base_hashers: []const H,
            base_log_size: u32,
            tail_columns: []const ColumnRef,
            final_log_size: u32,
            leaves: []H.Hash,
            start: usize,
            end: usize,
        };

        /// Builds lifted leaves while retaining only the largest native
        /// prefix-state layer that fits `prefix_state_budget_bytes`.
        ///
        /// The old streaming path retained one `H` for every final-domain
        /// row. That is fast because lower-height column prefixes are
        /// absorbed once at their native height, but costs 144 MiB of
        /// Poseidon state at log 21 before the 64 MiB leaf layer exists.
        /// A purely row-batched rebuild removes that state but replays all
        /// lower-height prefixes at final-domain multiplicity.
        ///
        /// This path keeps the useful half of both designs: native-height
        /// prefix reuse up to a checked byte cap, followed by an
        /// allocation-free parallel tail expansion directly into the
        /// final leaf layer. Its output is identical to `finalize()`.
        pub fn commitColumnsWithBoundedPrefix(
            self: *Committer,
            columns: []const ColumnRef,
            prefix_state_budget_bytes: usize,
            stats: ?*BoundedPrefixStats,
        ) !Self {
            if (columns.len == 0) {
                if (stats) |out| out.* = .{
                    .final_log_size = 0,
                    .prefix_log_size = 0,
                    .prefix_state_count = 1,
                    .prefix_state_bytes = @sizeOf(H),
                    .leaf_layer_bytes = @sizeOf(H.Hash),
                    .leaf_phase_peak_bytes = @sizeOf(H) + @sizeOf(H.Hash),
                };
                return self.finalize();
            }
            const seed_pair_bytes = try std.math.mul(usize, 2, @sizeOf(H));
            if (prefix_state_budget_bytes < seed_pair_bytes) {
                return error.PrefixStateBudgetTooSmall;
            }

            for (columns, 0..) |column, index| {
                if (!std.math.isPowerOfTwo(column.values.len) or column.values.len < 2) {
                    return error.InvalidColumnSize;
                }
                if (index > 0 and column.log_size < columns[index - 1].log_size) {
                    return error.InvalidColumnOrder;
                }
            }

            const final_log_size = columns[columns.len - 1].log_size;
            const final_leaf_count = @as(usize, 1) << @intCast(final_log_size);

            // Select only complete height groups. Splitting equal-height
            // columns across the boundary would preserve semantics, but it
            // would make the performance ledger shape/order dependent.
            var prefix_end: usize = 0;
            var group_start: usize = 0;
            while (group_start < columns.len) {
                const group_log_size = columns[group_start].log_size;
                var group_end = group_start + 1;
                while (group_end < columns.len and
                    columns[group_end].log_size == group_log_size)
                {
                    group_end += 1;
                }
                const state_count = @as(usize, 1) << @intCast(group_log_size);
                const state_bytes = std.math.mul(usize, state_count, @sizeOf(H)) catch
                    break;
                if (state_bytes > prefix_state_budget_bytes) break;
                prefix_end = group_end;
                group_start = group_end;
            }

            if (prefix_end > 0) {
                try self.addColumns(columns[0..prefix_end]);
            } else {
                // The lifted indexing contract starts from two independent
                // parity states at log 1. Both carry the same domain seed,
                // but keeping the pair makes every later mapping identical
                // to `addColumns`/`ExpandOps.expandHashers`.
                const seed = H.defaultWithInitialState();
                self.leaf_hashers = try self.allocator.alloc(H, 2);
                self.leaf_hashers[0] = seed;
                self.leaf_hashers[1] = seed;
                self.leaf_log_size = 1;
                self.initialized = true;
            }

            const prefix_state_count = self.leaf_hashers.len;
            const prefix_state_bytes = try std.math.mul(
                usize,
                prefix_state_count,
                @sizeOf(H),
            );
            const leaf_layer_bytes = try std.math.mul(
                usize,
                final_leaf_count,
                @sizeOf(H.Hash),
            );

            if (stats) |out| {
                var native_tail_absorptions: usize = 0;
                for (columns[prefix_end..]) |column| {
                    native_tail_absorptions = try std.math.add(
                        usize,
                        native_tail_absorptions,
                        column.values.len,
                    );
                }
                const tail_absorptions = try std.math.mul(
                    usize,
                    columns.len - prefix_end,
                    final_leaf_count,
                );
                out.* = .{
                    .final_log_size = final_log_size,
                    .prefix_log_size = self.leaf_log_size,
                    .prefix_column_count = prefix_end,
                    .tail_column_count = columns.len - prefix_end,
                    .prefix_state_count = prefix_state_count,
                    .prefix_state_bytes = prefix_state_bytes,
                    .leaf_layer_bytes = leaf_layer_bytes,
                    .leaf_phase_peak_bytes = try std.math.add(
                        usize,
                        prefix_state_bytes,
                        leaf_layer_bytes,
                    ),
                    .tail_absorptions = tail_absorptions,
                    .repeated_tail_absorptions = tail_absorptions - native_tail_absorptions,
                };
            }

            // When the cap admits the final native-height state layer,
            // retain the mature streaming implementation byte-for-byte.
            // The bounded tail is needed only when that layer would cross
            // the explicit cap.
            if (prefix_end == columns.len) return self.finalize();

            const layer_alloc = layerAllocator(self.allocator);
            const leaves = try layer_alloc.alloc(H.Hash, final_leaf_count);
            self.finalizeBoundedTail(
                columns[prefix_end..],
                final_log_size,
                leaves,
            );

            self.allocator.free(self.leaf_hashers);
            self.leaf_hashers = &[_]H{};
            const tree = try finishLeaves(self.allocator, layer_alloc, leaves);
            self.* = undefined;
            return tree;
        }

        fn finalizeBoundedTail(
            self: *Committer,
            tail_columns: []const ColumnRef,
            final_log_size: u32,
            leaves: []H.Hash,
        ) void {
            std.debug.assert(self.initialized);
            std.debug.assert(final_log_size >= self.leaf_log_size);
            std.debug.assert(leaves.len == @as(usize, 1) << @intCast(final_log_size));

            var requested_workers = parameters.parallelWorkersForLayer(
                leaves.len,
                merkleWorkerOverride(self.allocator),
            );
            const pool = if (requested_workers > 1) blk: {
                if (work_pool_mod.getGlobalPool()) |active| {
                    requested_workers = @min(requested_workers, active.workerCount());
                    break :blk if (requested_workers > 1) &active.pool else null;
                }
                break :blk LayerOps.sharedThreadPool();
            } else null;
            const worker_count = if (pool != null) requested_workers else 1;

            var ranges: [parameters.max_parallel_workers]BoundedTailRange = undefined;
            for (0..worker_count) |worker| {
                ranges[worker] = .{
                    .base_hashers = self.leaf_hashers,
                    .base_log_size = self.leaf_log_size,
                    .tail_columns = tail_columns,
                    .final_log_size = final_log_size,
                    .leaves = leaves,
                    .start = leaves.len * worker / worker_count,
                    .end = leaves.len * (worker + 1) / worker_count,
                };
            }

            if (worker_count == 1) {
                finalizeBoundedTailRange(&ranges[0]);
                return;
            }
            var wait_group: WaitGroup = .{};
            for (ranges[1..worker_count]) |*range| {
                pool.?.spawnWg(&wait_group, finalizeBoundedTailRange, .{
                    @as(*const BoundedTailRange, range),
                });
            }
            finalizeBoundedTailRange(&ranges[0]);
            wait_group.wait();
        }

        fn finalizeBoundedTailRange(range: *const BoundedTailRange) void {
            const base_shift: std.math.Log2Int(usize) = @intCast(
                range.final_log_size - range.base_log_size + 1,
            );
            var position = range.start;
            while (position < range.end) : (position += 1) {
                const base_index = ((position >> base_shift) << 1) + (position & 1);
                var hasher = range.base_hashers[base_index];
                for (range.tail_columns) |column| {
                    const column_shift: std.math.Log2Int(usize) = @intCast(
                        range.final_log_size - column.log_size + 1,
                    );
                    const source_index = ((position >> column_shift) << 1) +
                        (position & 1);
                    hasher.updateLeaf(column.values[source_index .. source_index + 1]);
                }
                range.leaves[position] = hasher.finalize();
            }
        }

        fn liftedTailStart(columns: []const ColumnRef) ?usize {
            if (comptime !@hasDecl(H, "domainPrefixBytes")) return null;
            if (H.domainPrefixBytes() != 64 or columns.len < 2) return null;

            const final_log_size = columns[columns.len - 1].log_size;
            var group_start: usize = 0;
            while (group_start < columns.len) {
                const log_size = columns[group_start].log_size;
                var group_end = group_start + 1;
                while (group_end < columns.len and
                    columns[group_end].log_size == log_size)
                {
                    group_end += 1;
                }
                if (group_end == columns.len) return null;

                const buffered_words = if ((group_end & 15) == 0)
                    @as(usize, 16)
                else
                    group_end & 15;
                const tail_columns = columns.len - group_end;
                if (final_log_size >= log_size + 2 and
                    tail_columns <= 16 - buffered_words and
                    tail_columns <= LeafOps.max_lifted_tail_columns)
                {
                    return group_end;
                }
                group_start = group_end;
            }
            return null;
        }

        fn finalizeLiftedTail(
            self: *Committer,
            tail_columns: []const ColumnRef,
        ) !Self {
            std.debug.assert(self.initialized);
            std.debug.assert(tail_columns.len > 0);
            const allocator = self.allocator;
            const layer_alloc = layerAllocator(allocator);
            const final_log_size = tail_columns[tail_columns.len - 1].log_size;
            std.debug.assert(final_log_size > self.leaf_log_size);
            const leaf_count = @as(usize, 1) << @intCast(final_log_size);
            const leaves = try layer_alloc.alloc(H.Hash, leaf_count);
            LeafOps.finalizeLiftedTail(
                self.leaf_hashers,
                self.leaf_log_size,
                tail_columns,
                final_log_size,
                leaves,
            );
            allocator.free(self.leaf_hashers);
            self.leaf_hashers = &[_]H{};

            const tree = try finishLeaves(allocator, layer_alloc, leaves);
            self.* = undefined;
            return tree;
        }

        fn finishLeaves(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            leaves: []H.Hash,
        ) !Self {
            const worker_override = merkleWorkerOverride(allocator);
            const reuse_pool = merklePoolReuseEnabled(allocator);

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| layer_alloc.free(layer);
            }
            try layers_bottom_up.append(allocator, leaves);

            if (leaves.len > 1) {
                std.debug.assert(std.math.isPowerOfTwo(leaves.len));
                const max_log_size = std.math.log2_int(usize, leaves.len);
                const max_out_len = leaves.len >> 1;
                var executor: LayerExecutor = undefined;
                executor.init(max_out_len, worker_override, reuse_pool);
                defer executor.deinit();

                var i: usize = 0;
                while (i < max_log_size) : (i += 1) {
                    const next_layer = try LayerOps.buildNextLayer(
                        layer_alloc,
                        layers_bottom_up.items[layers_bottom_up.items.len - 1],
                        &executor,
                        worker_override,
                    );
                    try layers_bottom_up.append(allocator, next_layer);
                }
            }

            const out_layers = try allocator.alloc([]H.Hash, layers_bottom_up.items.len);
            var i: usize = 0;
            while (i < out_layers.len) : (i += 1) {
                out_layers[i] = layers_bottom_up.items[out_layers.len - 1 - i];
            }
            return .{ .layers = out_layers, .layer_allocator = layer_alloc };
        }

        /// Finalize the streaming commitment: produce leaf hashes from the
        /// accumulated hasher state, build internal Merkle layers, and return
        /// the completed tree.  The `StreamingCommitter` is consumed (its
        /// hasher memory is freed).
        pub fn finalize(self: *Committer) !Self {
            const allocator = self.allocator;
            const layer_alloc = layerAllocator(allocator);
            if (!self.initialized) {
                // No columns were added — replicate the empty-column path
                // from buildLeaves.
                const seed_hasher = H.defaultWithInitialState();
                var h = seed_hasher;
                const leaves = try layer_alloc.alloc(H.Hash, 1);
                leaves[0] = h.finalize();
                const tree = try finishLeaves(allocator, layer_alloc, leaves);
                self.* = undefined;
                return tree;
            }

            // Finalize leaf hashers into leaf hashes.
            const leaf_count = self.leaf_hashers.len;
            const leaves = try layer_alloc.alloc(H.Hash, leaf_count);
            LeafOps.finalizeHashers(self.leaf_hashers, leaves);
            // Free hasher state — column data is no longer needed.
            allocator.free(self.leaf_hashers);
            self.leaf_hashers = &[_]H{};
            const tree = try finishLeaves(allocator, layer_alloc, leaves);
            self.* = undefined;
            return tree;
        }
    };
}
