//! Leaf construction for lifted Merkle commitments.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const work_pool_mod = @import("../work_pool.zig");
const columns_mod = @import("columns.zig");
const layers_mod = @import("layers.zig");
const parameters = @import("parameters.zig");
const blake2_stream4 = @import("blake2_stream4.zig");

pub fn Operations(comptime H: type) type {
    return struct {
        const ColumnRef = columns_mod.ColumnRef;
        const LayerOps = layers_mod.Operations(H);
        const ThreadPool = std.Thread.Pool;
        const WaitGroup = std.Thread.WaitGroup;
        const parallel_min_nodes = parameters.parallel_min_nodes;
        const parallel_min_nodes_per_worker = parameters.parallel_min_nodes_per_worker;
        const max_parallel_workers = parameters.max_parallel_workers;
        const leaf_tile_len = parameters.leaf_tile_len;
        const max_leaf_scratch_bytes = parameters.max_leaf_scratch_bytes;

        pub fn build(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            sorted_columns: []const ColumnRef,
        ) ![]H.Hash {
            var seed_hasher = H.defaultWithInitialState();
            if (sorted_columns.len == 0) {
                const layer = try layer_alloc.alloc(H.Hash, 1);
                layer[0] = seed_hasher.finalize();
                return layer;
            }

            if (sorted_columns[0].values.len == 1) return error.InvalidColumnSize;

            var prev_layer = try allocator.alloc(H, 2);
            prev_layer[0] = seed_hasher;
            prev_layer[1] = seed_hasher;

            var prev_layer_log_size: u32 = 1;
            var group_start: usize = 0;
            while (group_start < sorted_columns.len) {
                const log_size = sorted_columns[group_start].log_size;
                var group_end = group_start + 1;
                while (group_end < sorted_columns.len and
                    sorted_columns[group_end].log_size == log_size)
                {
                    group_end += 1;
                }

                const log_ratio = log_size - prev_layer_log_size;
                const layer_size = @as(usize, 1) << @intCast(log_size);
                const shift_amt: std.math.Log2Int(usize) = @intCast(log_ratio + 1);
                const expanded = try allocator.alloc(H, layer_size);
                for (0..layer_size) |idx| {
                    const src_idx = ((idx >> shift_amt) << 1) + (idx & 1);
                    expanded[idx] = prev_layer[src_idx];
                }
                allocator.free(prev_layer);
                prev_layer = expanded;

                const group_columns = sorted_columns[group_start..group_end];
                if (comptime @hasDecl(H, "updateLeafPackedBytes")) {
                    try updateHashersPacked(
                        allocator,
                        prev_layer,
                        group_columns,
                        layer_size,
                    );
                } else {
                    var idx: usize = 0;
                    while (idx < layer_size) : (idx += 1) {
                        for (group_columns) |column| {
                            prev_layer[idx].updateLeaf(column.values[idx .. idx + 1]);
                        }
                    }
                }

                prev_layer_log_size = log_size;
                group_start = group_end;
            }

            // Output layer uses mmap-backed allocator for sequential-read
            // hinting; temporary hasher arrays above use the regular allocator.
            const out = try layer_alloc.alloc(H.Hash, prev_layer.len);
            finalizeHashers(prev_layer, out);
            allocator.free(prev_layer);
            return out;
        }

        /// Builds leaf hashes in row batches to bound peak memory.
        ///
        /// Instead of allocating one hasher per leaf for the entire column
        /// set (which can be hundreds of MiB for large domains), this
        /// function processes `batch_size` leaves at a time:
        ///
        /// 1. Allocate a small hasher array of length `batch_size`.
        /// 2. For each column, compute the correct value mapping for the
        ///    current row range and feed it into the batch hashers.
        /// 3. Finalize the batch and write leaf hashes to the output.
        /// 4. Reuse the hasher array for the next batch.
        ///
        /// The mapping from leaf position `pos` (in the max-log-size
        /// domain) to a column at `col_log_size` is:
        ///
        ///   column_index = ((pos >> (max_log_size - col_log_size + 1)) << 1) + (pos & 1)
        ///
        /// This matches the lifting index used by the decommit path and
        /// produces bit-identical leaf hashes.
        const BatchedLeafRangeCtx = struct {
            seed_hasher: H,
            sorted_columns: []const ColumnRef,
            max_log_size: u32,
            out: []H.Hash,
            batch_hashers: []H,
            scratch: ?[]align(@alignOf(M31)) u8,
            start: usize,
            end: usize,
        };

        fn buildLeavesBatchedRange(ctx: *const BatchedLeafRangeCtx) void {
            if (comptime @hasDecl(H, "leafSeed") and @hasDecl(H, "hashPackedLeavesWithSeed4")) {
                buildLeavesBatchedRange4(ctx);
                return;
            }
            var batch_start = ctx.start;
            while (batch_start < ctx.end) : (batch_start += ctx.batch_hashers.len) {
                const batch_end = @min(ctx.end, batch_start + ctx.batch_hashers.len);
                const batch_len = batch_end - batch_start;
                for (ctx.batch_hashers[0..batch_len]) |*hasher| hasher.* = ctx.seed_hasher;

                for (ctx.sorted_columns) |column| {
                    const shift_amt: std.math.Log2Int(usize) = @intCast(ctx.max_log_size - column.log_size + 1);
                    if (comptime @hasDecl(H, "updateLeafPackedBytes")) {
                        const scratch = ctx.scratch orelse {
                            for (0..batch_len) |local| {
                                const position = batch_start + local;
                                const column_index = ((position >> shift_amt) << 1) + (position & 1);
                                ctx.batch_hashers[local].updateLeaf(column.values[column_index .. column_index + 1]);
                            }
                            continue;
                        };
                        const max_tile = max_leaf_scratch_bytes / @sizeOf(M31);
                        var tile_offset: usize = 0;
                        while (tile_offset < batch_len) : (tile_offset += max_tile) {
                            const tile_len = @min(max_tile, batch_len - tile_offset);
                            const buffer = scratch[0 .. tile_len * @sizeOf(M31)];
                            if (builtin.cpu.arch.endian() == .little) {
                                const words = std.mem.bytesAsSlice(M31, buffer);
                                for (0..tile_len) |local| {
                                    const position = batch_start + tile_offset + local;
                                    const column_index = ((position >> shift_amt) << 1) + (position & 1);
                                    words[local] = column.values[column_index];
                                }
                            } else {
                                for (0..tile_len) |local| {
                                    const position = batch_start + tile_offset + local;
                                    const column_index = ((position >> shift_amt) << 1) + (position & 1);
                                    const encoded = column.values[column_index].toBytesLe();
                                    const byte_start = local * @sizeOf(M31);
                                    @memcpy(buffer[byte_start .. byte_start + @sizeOf(M31)], encoded[0..]);
                                }
                            }
                            for (0..tile_len) |local| {
                                const byte_start = local * @sizeOf(M31);
                                ctx.batch_hashers[tile_offset + local].updateLeafPackedBytes(
                                    buffer[byte_start .. byte_start + @sizeOf(M31)],
                                );
                            }
                        }
                    } else {
                        for (0..batch_len) |local| {
                            const position = batch_start + local;
                            const column_index = ((position >> shift_amt) << 1) + (position & 1);
                            ctx.batch_hashers[local].updateLeaf(column.values[column_index .. column_index + 1]);
                        }
                    }
                }

                for (ctx.batch_hashers[0..batch_len], 0..) |*hasher, local| {
                    ctx.out[batch_start + local] = hasher.finalize();
                }
            }
        }

        fn buildLeavesBatchedRange4(ctx: *const BatchedLeafRangeCtx) void {
            if (comptime @hasDecl(H, "hashDirectM31LeavesWithSeed4")) {
                var direct = true;
                for (ctx.sorted_columns) |column| {
                    if (column.log_size != ctx.max_log_size) {
                        direct = false;
                        break;
                    }
                }
                if (direct) {
                    buildLeavesDirectRange4(ctx);
                    return;
                }
            }
            const scratch = ctx.scratch orelse {
                buildLeavesBatchedRangeScalar(ctx);
                return;
            };
            const bytes_per_leaf = ctx.sorted_columns.len * @sizeOf(M31);
            if (bytes_per_leaf == 0 or 4 * bytes_per_leaf > scratch.len) {
                buildLeavesBatchedRangeScalar(ctx);
                return;
            }

            const seed = H.leafSeed();
            var position = ctx.start;
            while (position + 4 <= ctx.end) : (position += 4) {
                const buffer = scratch[0 .. 4 * bytes_per_leaf];
                packBatchedLeafMessages(ctx, buffer, position, 4, bytes_per_leaf);
                var messages: [4][]const u8 = undefined;
                for (0..4) |lane| {
                    messages[lane] = buffer[lane * bytes_per_leaf ..][0..bytes_per_leaf];
                }
                const hashes = H.hashPackedLeavesWithSeed4(seed, &messages);
                inline for (0..4) |lane| ctx.out[position + lane] = hashes[lane];
            }

            while (position < ctx.end) : (position += 1) {
                var hasher = ctx.seed_hasher;
                for (ctx.sorted_columns) |column| {
                    const shift_amt: std.math.Log2Int(usize) = @intCast(ctx.max_log_size - column.log_size + 1);
                    const source_index = ((position >> shift_amt) << 1) + (position & 1);
                    hasher.updateLeaf(column.values[source_index .. source_index + 1]);
                }
                ctx.out[position] = hasher.finalize();
            }
        }

        fn buildLeavesDirectRange4(ctx: *const BatchedLeafRangeCtx) void {
            const seed = H.leafSeed();
            var position = ctx.start;
            while (position + 4 <= ctx.end) : (position += 4) {
                const hashes = H.hashDirectM31LeavesWithSeed4(
                    seed,
                    ctx.sorted_columns,
                    position,
                );
                inline for (0..4) |lane| ctx.out[position + lane] = hashes[lane];
            }
            while (position < ctx.end) : (position += 1) {
                var hasher = ctx.seed_hasher;
                for (ctx.sorted_columns) |column| {
                    hasher.updateLeaf(column.values[position .. position + 1]);
                }
                ctx.out[position] = hasher.finalize();
            }
        }

        fn packBatchedLeafMessages(
            ctx: *const BatchedLeafRangeCtx,
            buffer: []align(@alignOf(M31)) u8,
            position: usize,
            lane_count: usize,
            bytes_per_leaf: usize,
        ) void {
            if (builtin.cpu.arch.endian() == .little) {
                const words = std.mem.bytesAsSlice(M31, buffer);
                for (0..lane_count) |lane| {
                    for (ctx.sorted_columns, 0..) |column, column_index| {
                        const shift_amt: std.math.Log2Int(usize) = @intCast(ctx.max_log_size - column.log_size + 1);
                        const leaf_position = position + lane;
                        const source_index = ((leaf_position >> shift_amt) << 1) + (leaf_position & 1);
                        words[lane * ctx.sorted_columns.len + column_index] = column.values[source_index];
                    }
                }
                return;
            }
            for (0..lane_count) |lane| {
                for (ctx.sorted_columns, 0..) |column, column_index| {
                    const shift_amt: std.math.Log2Int(usize) = @intCast(ctx.max_log_size - column.log_size + 1);
                    const leaf_position = position + lane;
                    const source_index = ((leaf_position >> shift_amt) << 1) + (leaf_position & 1);
                    const encoded = column.values[source_index].toBytesLe();
                    const start = lane * bytes_per_leaf + column_index * @sizeOf(M31);
                    @memcpy(buffer[start .. start + @sizeOf(M31)], encoded[0..]);
                }
            }
        }

        fn buildLeavesBatchedRangeScalar(ctx: *const BatchedLeafRangeCtx) void {
            var position = ctx.start;
            while (position < ctx.end) : (position += 1) {
                var hasher = ctx.seed_hasher;
                for (ctx.sorted_columns) |column| {
                    const shift_amt: std.math.Log2Int(usize) = @intCast(ctx.max_log_size - column.log_size + 1);
                    const source_index = ((position >> shift_amt) << 1) + (position & 1);
                    hasher.updateLeaf(column.values[source_index .. source_index + 1]);
                }
                ctx.out[position] = hasher.finalize();
            }
        }

        pub fn buildBatched(
            allocator: std.mem.Allocator,
            layer_alloc: std.mem.Allocator,
            sorted_columns: []const ColumnRef,
            batch_size: usize,
        ) ![]H.Hash {
            var seed_hasher = H.defaultWithInitialState();
            if (sorted_columns.len == 0) {
                const layer = try layer_alloc.alloc(H.Hash, 1);
                layer[0] = seed_hasher.finalize();
                return layer;
            }

            if (sorted_columns[0].values.len == 1) return error.InvalidColumnSize;

            // The maximum log size determines the total leaf count.
            const max_log_size: u32 = sorted_columns[sorted_columns.len - 1].log_size;
            const total_leaves: usize = @as(usize, 1) << @intCast(max_log_size);

            const out = try layer_alloc.alloc(H.Hash, total_leaves);
            errdefer layer_alloc.free(out);

            const pool = work_pool_mod.getGlobalPool();
            const worker_capacity = total_leaves / parallel_min_nodes_per_worker;
            const worker_count = if (pool) |active_pool|
                @max(@as(usize, 1), @min(active_pool.workerCount(), worker_capacity))
            else
                1;
            const per_worker_batch = @min(@min(batch_size, total_leaves), @as(usize, 1024));
            const four_way_hashing = comptime @hasDecl(H, "leafSeed") and
                @hasDecl(H, "hashPackedLeavesWithSeed4");
            const hashers_per_worker = if (four_way_hashing) 0 else per_worker_batch;
            const hashers = try allocator.alloc(H, worker_count * hashers_per_worker);
            defer allocator.free(hashers);
            const scratch_words_per_worker = if (four_way_hashing)
                try std.math.mul(usize, 4, sorted_columns.len)
            else
                max_leaf_scratch_bytes / @sizeOf(M31);
            const scratch_words = if (comptime @hasDecl(H, "updateLeafPackedBytes"))
                allocator.alloc(M31, worker_count * scratch_words_per_worker) catch null
            else
                null;
            defer if (scratch_words) |words| allocator.free(words);

            var contexts: [max_parallel_workers]BatchedLeafRangeCtx = undefined;
            const batches = (total_leaves + per_worker_batch - 1) / per_worker_batch;
            const batches_per_worker = (batches + worker_count - 1) / worker_count;
            for (0..worker_count) |worker| {
                const start = @min(total_leaves, worker * batches_per_worker * per_worker_batch);
                const end = @min(total_leaves, start + batches_per_worker * per_worker_batch);
                contexts[worker] = .{
                    .seed_hasher = seed_hasher,
                    .sorted_columns = sorted_columns,
                    .max_log_size = max_log_size,
                    .out = out,
                    .batch_hashers = hashers[worker * hashers_per_worker ..][0..hashers_per_worker],
                    .scratch = if (scratch_words) |words| blk: {
                        const scratch_start = worker * scratch_words_per_worker;
                        break :blk std.mem.sliceAsBytes(words[scratch_start..][0..scratch_words_per_worker]);
                    } else null,
                    .start = start,
                    .end = end,
                };
            }

            if (worker_count > 1) {
                var wait_group: WaitGroup = .{};
                for (contexts[1..worker_count]) |*ctx| {
                    pool.?.spawnWg(&wait_group, buildLeavesBatchedRange, .{@as(*const BatchedLeafRangeCtx, ctx)});
                }
                buildLeavesBatchedRange(&contexts[0]);
                wait_group.wait();
            } else {
                buildLeavesBatchedRange(&contexts[0]);
            }

            return out;
        }

        pub const max_lifted_tail_columns: usize = 15;

        const LiftedTailRangeCtx = struct {
            base_hashers: []const H,
            base_log_size: u32,
            tail_columns: []const ColumnRef,
            final_log_size: u32,
            out: []H.Hash,
            start: usize,
            end: usize,
        };

        fn liftedTailBaseIndex(ctx: *const LiftedTailRangeCtx, position: usize) usize {
            const base_shift: std.math.Log2Int(usize) = @intCast(
                ctx.final_log_size - ctx.base_log_size + 1,
            );
            return ((position >> base_shift) << 1) + (position & 1);
        }

        fn fillLiftedTailValues(
            ctx: *const LiftedTailRangeCtx,
            position: usize,
            values: *[max_lifted_tail_columns]M31,
        ) void {
            for (ctx.tail_columns, 0..) |column, column_index| {
                const column_shift: std.math.Log2Int(usize) = @intCast(
                    ctx.final_log_size - column.log_size + 1,
                );
                const source_index = ((position >> column_shift) << 1) + (position & 1);
                values[column_index] = column.values[source_index];
            }
        }

        fn finalizeLiftedTailOne(ctx: *const LiftedTailRangeCtx, position: usize) void {
            var tail_values: [max_lifted_tail_columns]M31 = undefined;
            fillLiftedTailValues(ctx, position, &tail_values);
            var hasher = ctx.base_hashers[liftedTailBaseIndex(ctx, position)];
            hasher.updateLeaf(tail_values[0..ctx.tail_columns.len]);
            ctx.out[position] = hasher.finalize();
        }

        fn finalizeLiftedTailRange(ctx: *const LiftedTailRangeCtx) void {
            var position = ctx.start;

            if (comptime blake2_stream4.supports(H)) {
                while (position < ctx.end and (position & 3) != 0) : (position += 1) {
                    finalizeLiftedTailOne(ctx, position);
                }
                while (position + 4 <= ctx.end) : (position += 4) {
                    var hashers: [4]H = undefined;
                    var tail_storage: [4][max_lifted_tail_columns]M31 = undefined;
                    var tail_views: [4][]const M31 = undefined;
                    inline for (0..4) |lane| {
                        const lane_position = position + lane;
                        hashers[lane] = ctx.base_hashers[liftedTailBaseIndex(ctx, lane_position)];
                        fillLiftedTailValues(ctx, lane_position, &tail_storage[lane]);
                        tail_views[lane] = tail_storage[lane][0..ctx.tail_columns.len];
                    }
                    const hashes = blake2_stream4.finalizeTail4(&hashers, &tail_views);
                    inline for (0..4) |lane| ctx.out[position + lane] = hashes[lane];
                }
            }

            while (position < ctx.end) : (position += 1) {
                finalizeLiftedTailOne(ctx, position);
            }
        }

        /// Finalizes a lifted leaf layer without materializing intermediate
        /// hasher arrays when the remaining M31 values fit in the current
        /// terminal hash block. The caller proves that no compression occurs
        /// between `base_hashers` and finalization.
        pub fn finalizeLiftedTail(
            base_hashers: []const H,
            base_log_size: u32,
            tail_columns: []const ColumnRef,
            final_log_size: u32,
            out: []H.Hash,
        ) void {
            std.debug.assert(tail_columns.len > 0);
            std.debug.assert(tail_columns.len <= max_lifted_tail_columns);
            std.debug.assert(out.len == @as(usize, 1) << @intCast(final_log_size));

            const pool = work_pool_mod.getGlobalPool();
            const worker_capacity = out.len / parallel_min_nodes_per_worker;
            const worker_count = if (pool) |active_pool|
                @max(@as(usize, 1), @min(active_pool.workerCount(), worker_capacity))
            else
                1;
            var contexts: [max_parallel_workers]LiftedTailRangeCtx = undefined;
            for (0..worker_count) |worker| {
                const start = out.len * worker / worker_count;
                const end = out.len * (worker + 1) / worker_count;
                contexts[worker] = .{
                    .base_hashers = base_hashers,
                    .base_log_size = base_log_size,
                    .tail_columns = tail_columns,
                    .final_log_size = final_log_size,
                    .out = out,
                    .start = start,
                    .end = end,
                };
            }

            if (worker_count > 1) {
                var wait_group: WaitGroup = .{};
                for (contexts[1..worker_count]) |*ctx| {
                    pool.?.spawnWg(&wait_group, finalizeLiftedTailRange, .{
                        @as(*const LiftedTailRangeCtx, ctx),
                    });
                }
                finalizeLiftedTailRange(&contexts[0]);
                wait_group.wait();
            } else {
                finalizeLiftedTailRange(&contexts[0]);
            }
        }

        const FinalizeRangeCtx = struct {
            hashers: []H,
            out: []H.Hash,
            start: usize,
            end: usize,
        };

        fn finalizeRange(ctx: *const FinalizeRangeCtx) void {
            var i = ctx.start;
            if (comptime blake2_stream4.supports(H)) {
                while (i + 4 <= ctx.end) : (i += 4) {
                    const hashers: *const [4]H = @ptrCast(ctx.hashers.ptr + i);
                    const hashes = blake2_stream4.finalize4(hashers);
                    inline for (0..4) |lane| ctx.out[i + lane] = hashes[lane];
                }
            }
            while (i < ctx.end) : (i += 1) {
                ctx.out[i] = ctx.hashers[i].finalize();
            }
        }

        fn finalizeRangeThread(ctx: *const FinalizeRangeCtx) void {
            finalizeRange(ctx);
        }

        pub fn finalizeHashers(hashers: []H, out: []H.Hash) void {
            std.debug.assert(hashers.len == out.len);
            if (hashers.len < parallel_min_nodes or builtin.single_threaded) {
                for (hashers, 0..) |*hasher, i| out[i] = hasher.finalize();
                return;
            }
            finalizeHashersParallel(hashers, out);
        }

        fn finalizeHashersParallel(hashers: []H, out: []H.Hash) void {
            std.debug.assert(hashers.len >= parallel_min_nodes);

            const worker_count = blk: {
                const capacity = hashers.len / parallel_min_nodes_per_worker;
                if (capacity < 2) break :blk @as(usize, 1);
                const cpu_count = std.Thread.getCpuCount() catch break :blk @as(usize, 1);
                break :blk @min(@min(cpu_count, capacity), max_parallel_workers);
            };

            if (worker_count <= 1) {
                for (hashers, 0..) |*h, i| out[i] = h.finalize();
                return;
            }

            // Try to use the unified global pool first, then the Merkle shared pool.
            const pool_ptr: *ThreadPool = blk: {
                if (work_pool_mod.getGlobalPool()) |global_pool| {
                    break :blk &global_pool.pool;
                }
                break :blk LayerOps.sharedThreadPool() orelse {
                    for (hashers, 0..) |*h, i| out[i] = h.finalize();
                    return;
                };
            };

            var contexts: [max_parallel_workers]FinalizeRangeCtx = undefined;
            const chunk_len = (hashers.len + worker_count - 1) / worker_count;
            var actual_workers: usize = 0;
            var start: usize = 0;
            while (start < hashers.len and actual_workers < worker_count) : (actual_workers += 1) {
                const end = @min(hashers.len, start + chunk_len);
                contexts[actual_workers] = FinalizeRangeCtx{
                    .hashers = hashers,
                    .out = out,
                    .start = start,
                    .end = end,
                };
                start = end;
            }
            if (actual_workers <= 1) {
                finalizeRange(&contexts[0]);
                return;
            }

            var wait_group: WaitGroup = .{};
            for (1..actual_workers) |i| {
                pool_ptr.spawnWg(&wait_group, finalizeRangeThread, .{&contexts[i]});
            }
            finalizeRange(&contexts[0]);
            wait_group.wait();
        }

        const PackedLeafRangeCtx = struct {
            scratch: []align(@alignOf(M31)) u8,
            leaf_hashers: []H,
            group_columns: []const ColumnRef,
            start: usize,
            end: usize,
        };

        fn updateLeafHashersPackedRange(ctx: *const PackedLeafRangeCtx) void {
            var tile_start = ctx.start;
            while (tile_start < ctx.end) : (tile_start += leaf_tile_len) {
                const tile_end = @min(ctx.end, tile_start + leaf_tile_len);
                const tile_size = tile_end - tile_start;
                const max_chunk_columns = @max(
                    @as(usize, 1),
                    max_leaf_scratch_bytes / (tile_size * @sizeOf(M31)),
                );

                var column_start: usize = 0;
                while (column_start < ctx.group_columns.len) {
                    const column_end = @min(ctx.group_columns.len, column_start + max_chunk_columns);
                    const column_chunk = ctx.group_columns[column_start..column_end];

                    if (comptime blake2_stream4.supports(H)) {
                        var local_leaf: usize = 0;
                        while (local_leaf + 4 <= tile_size) : (local_leaf += 4) {
                            const hashers: *[4]H = @ptrCast(
                                ctx.leaf_hashers.ptr + tile_start + local_leaf,
                            );
                            blake2_stream4.updateM31Columns4(
                                hashers,
                                column_chunk,
                                tile_start + local_leaf,
                            );
                        }
                        while (local_leaf < tile_size) : (local_leaf += 1) {
                            const leaf_index = tile_start + local_leaf;
                            for (column_chunk) |column| {
                                ctx.leaf_hashers[leaf_index].updateLeaf(
                                    column.values[leaf_index .. leaf_index + 1],
                                );
                            }
                        }
                        column_start = column_end;
                        continue;
                    }

                    const bytes_per_leaf = column_chunk.len * @sizeOf(M31);
                    const scratch_len = tile_size * bytes_per_leaf;
                    packLeafTileBytes(
                        ctx.scratch[0..scratch_len],
                        column_chunk,
                        tile_start,
                        tile_size,
                    );

                    var local_leaf: usize = 0;
                    while (local_leaf < tile_size) : (local_leaf += 1) {
                        const byte_start = local_leaf * bytes_per_leaf;
                        ctx.leaf_hashers[tile_start + local_leaf].updateLeafPackedBytes(
                            ctx.scratch[byte_start .. byte_start + bytes_per_leaf],
                        );
                    }
                    column_start = column_end;
                }
            }
        }

        pub fn updateHashersPacked(
            allocator: std.mem.Allocator,
            leaf_hashers: []H,
            group_columns: []const ColumnRef,
            layer_size: usize,
        ) !void {
            const pool = work_pool_mod.getGlobalPool();
            const worker_count = if (pool) |active_pool|
                @min(active_pool.workerCount(), layer_size / parallel_min_nodes_per_worker)
            else
                1;
            const actual_workers = @max(@as(usize, 1), worker_count);
            const scratch_words_per_worker = max_leaf_scratch_bytes / @sizeOf(M31);
            const scratch_words = try allocator.alloc(M31, actual_workers * scratch_words_per_worker);
            defer allocator.free(scratch_words);

            var contexts: [max_parallel_workers]PackedLeafRangeCtx = undefined;
            const tiles = (layer_size + leaf_tile_len - 1) / leaf_tile_len;
            const tiles_per_worker = (tiles + actual_workers - 1) / actual_workers;
            for (0..actual_workers) |worker| {
                const start = @min(layer_size, worker * tiles_per_worker * leaf_tile_len);
                const end = @min(layer_size, start + tiles_per_worker * leaf_tile_len);
                const scratch_start = worker * scratch_words_per_worker;
                contexts[worker] = .{
                    .scratch = std.mem.sliceAsBytes(scratch_words[scratch_start..][0..scratch_words_per_worker]),
                    .leaf_hashers = leaf_hashers,
                    .group_columns = group_columns,
                    .start = start,
                    .end = end,
                };
            }

            if (actual_workers > 1) {
                var wait_group: WaitGroup = .{};
                for (contexts[1..actual_workers]) |*ctx| {
                    pool.?.spawnWg(&wait_group, updateLeafHashersPackedRange, .{@as(*const PackedLeafRangeCtx, ctx)});
                }
                updateLeafHashersPackedRange(&contexts[0]);
                wait_group.wait();
                return;
            }
            updateLeafHashersPackedRange(&contexts[0]);
        }

        fn packLeafTileBytes(
            scratch: []align(@alignOf(M31)) u8,
            column_chunk: []const ColumnRef,
            tile_start: usize,
            tile_size: usize,
        ) void {
            const bytes_per_leaf = column_chunk.len * @sizeOf(M31);
            std.debug.assert(scratch.len == tile_size * bytes_per_leaf);

            if (builtin.cpu.arch.endian() == .little) {
                const scratch_words = std.mem.bytesAsSlice(M31, scratch);
                var local_leaf: usize = 0;
                while (local_leaf < tile_size) : (local_leaf += 1) {
                    const leaf_words = scratch_words[local_leaf * column_chunk.len ..][0..column_chunk.len];
                    const leaf_index = tile_start + local_leaf;
                    for (column_chunk, 0..) |column, column_idx| {
                        leaf_words[column_idx] = column.values[leaf_index];
                    }
                }
                return;
            }

            var local_leaf: usize = 0;
            while (local_leaf < tile_size) : (local_leaf += 1) {
                const leaf_index = tile_start + local_leaf;
                const leaf_start = local_leaf * bytes_per_leaf;
                for (column_chunk, 0..) |column, column_idx| {
                    const encoded = column.values[leaf_index].toBytesLe();
                    const byte_start = leaf_start + (column_idx * @sizeOf(M31));
                    @memcpy(scratch[byte_start .. byte_start + @sizeOf(M31)], encoded[0..]);
                }
            }
        }
    };
}
