const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("../../core/fields/m31.zig");
const lifted_merkle_hasher = @import("../../core/vcs_lifted/merkle_hasher.zig");
const vcs_lifted_verifier = @import("../../core/vcs_lifted/verifier.zig");

const M31 = m31.M31;

pub fn MerkleProverLifted(comptime H: type) type {
    comptime lifted_merkle_hasher.assertMerkleHasherLifted(H);
    return struct {
        /// Merkle layers from root to largest layer.
        layers: [][]H.Hash,

        const Self = @This();
        const NodeValue = vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue;
        const ExtendedDecommitment = vcs_lifted_verifier.ExtendedMerkleDecommitmentLifted(H);
        const Decommitment = vcs_lifted_verifier.MerkleDecommitmentLifted(H);
        const parallel_min_nodes: usize = 1 << 13;
        const parallel_min_nodes_per_worker: usize = 1 << 12;
        const max_parallel_workers: usize = 16;
        const ThreadPool = std.Thread.Pool;
        const WaitGroup = std.Thread.WaitGroup;

        pub const DecommitmentResult = struct {
            queried_values: [][]M31,
            decommitment: ExtendedDecommitment,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                for (self.queried_values) |column| allocator.free(column);
                allocator.free(self.queried_values);
                self.decommitment.deinit(allocator);
                self.* = undefined;
            }
        };

        const LayerExecutor = struct {
            enabled: bool = false,
            max_workers: usize = 1,
            pool: ThreadPool = undefined,

            fn init(self: *LayerExecutor, max_workers: usize) void {
                self.* = .{
                    .enabled = false,
                    .max_workers = max_workers,
                };
                if (builtin.single_threaded or max_workers <= 1) return;

                self.pool.init(.{
                    // Keep pool task allocation decoupled from caller allocators
                    // (including test allocators) to avoid cross-thread contention.
                    .allocator = std.heap.page_allocator,
                    // Previous implementation used one caller worker + N-1 spawned workers.
                    .n_jobs = max_workers - 1,
                }) catch return;
                self.enabled = true;
            }

            fn deinit(self: *LayerExecutor) void {
                if (self.enabled) {
                    self.pool.deinit();
                }
                self.* = undefined;
            }
        };

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.layers) |layer| allocator.free(layer);
            allocator.free(self.layers);
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return self.layers[0][0];
        }

        pub fn commit(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            return commitWithWorkerOverride(allocator, columns, merkleWorkerOverride(allocator));
        }

        fn commitWithWorkerOverride(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            worker_override: ?usize,
        ) !Self {
            const sorted = try sortColumnsByLogSizeAsc(allocator, columns);
            defer allocator.free(sorted);

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| allocator.free(layer);
            }

            const leaves = try buildLeaves(allocator, sorted);
            try layers_bottom_up.append(allocator, leaves);

            if (leaves.len > 1) {
                std.debug.assert(std.math.isPowerOfTwo(leaves.len));
                const max_log_size = std.math.log2_int(usize, leaves.len);
                const max_out_len = leaves.len >> 1;
                var executor: LayerExecutor = undefined;
                executor.init(parallelWorkersForLayer(max_out_len, worker_override));
                defer executor.deinit();

                var i: usize = 0;
                while (i < max_log_size) : (i += 1) {
                    const next_layer = try buildNextLayer(
                        allocator,
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
            return .{ .layers = out_layers };
        }

        fn merkleWorkerOverride(allocator: std.mem.Allocator) ?usize {
            const raw = std.process.getEnvVarOwned(allocator, "STWO_ZIG_MERKLE_WORKERS") catch return null;
            defer allocator.free(raw);
            const parsed = std.fmt.parseInt(usize, raw, 10) catch return null;
            if (parsed == 0) return null;
            return parsed;
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            columns: []const []const M31,
        ) !DecommitmentResult {
            const max_log_size_u32: u32 = @intCast(self.layers.len - 1);

            const queried_values = try allocator.alloc([]M31, columns.len);
            var queried_values_initialized: usize = 0;
            errdefer {
                for (queried_values[0..queried_values_initialized]) |column| allocator.free(column);
                allocator.free(queried_values);
            }

            for (columns, 0..) |column, i| {
                if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
                    return error.InvalidColumnSize;
                }
                const log_size: u32 = @intCast(std.math.log2_int(usize, column.len));
                if (log_size > max_log_size_u32) return error.InvalidColumnSize;
                const shift = max_log_size_u32 - log_size;
                const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);

                queried_values[i] = try allocator.alloc(M31, query_positions.len);
                queried_values_initialized += 1;
                for (query_positions, 0..) |position, j| {
                    const column_index = ((position >> shift_amt) << 1) + (position & 1);
                    queried_values[i][j] = column[column_index];
                }
            }

            var hash_witness = std.ArrayList(H.Hash).empty;
            defer hash_witness.deinit(allocator);

            var all_node_values = std.ArrayList([]NodeValue).empty;
            defer {
                for (all_node_values.items) |layer| allocator.free(layer);
                all_node_values.deinit(allocator);
            }

            var prev_layer_queries = std.ArrayList(usize).empty;
            defer prev_layer_queries.deinit(allocator);
            for (query_positions, 0..) |position, i| {
                if (i == 0 or query_positions[i - 1] != position) {
                    try prev_layer_queries.append(allocator, position);
                }
            }

            var layer_log_size: i64 = @intCast(self.layers.len);
            layer_log_size -= 2;
            while (layer_log_size >= 0) : (layer_log_size -= 1) {
                const prev_layer_hashes = self.layers[@intCast(layer_log_size + 1)];

                var curr_layer_queries = std.ArrayList(usize).empty;
                defer curr_layer_queries.deinit(allocator);

                var all_node_values_for_layer = std.ArrayList(NodeValue).empty;
                defer all_node_values_for_layer.deinit(allocator);

                var p: usize = 0;
                while (p < prev_layer_queries.items.len) {
                    const first = prev_layer_queries.items[p];
                    var chunk_len: usize = 1;
                    if (p + 1 < prev_layer_queries.items.len and
                        ((first ^ 1) == prev_layer_queries.items[p + 1]))
                    {
                        chunk_len = 2;
                    }

                    if (chunk_len == 1) {
                        try hash_witness.append(allocator, prev_layer_hashes[first ^ 1]);
                    }

                    const curr_index = first >> 1;
                    try curr_layer_queries.append(allocator, curr_index);
                    try all_node_values_for_layer.append(allocator, .{
                        .index = 2 * curr_index,
                        .hash = prev_layer_hashes[2 * curr_index],
                    });
                    try all_node_values_for_layer.append(allocator, .{
                        .index = 2 * curr_index + 1,
                        .hash = prev_layer_hashes[2 * curr_index + 1],
                    });
                    p += chunk_len;
                }

                prev_layer_queries.clearRetainingCapacity();
                try prev_layer_queries.appendSlice(allocator, curr_layer_queries.items);

                try all_node_values.append(allocator, try all_node_values_for_layer.toOwnedSlice(allocator));
            }

            const hash_witness_owned = try hash_witness.toOwnedSlice(allocator);
            errdefer allocator.free(hash_witness_owned);

            const all_node_values_owned = try all_node_values.toOwnedSlice(allocator);
            errdefer {
                for (all_node_values_owned) |layer| allocator.free(layer);
                allocator.free(all_node_values_owned);
            }

            return .{
                .queried_values = queried_values,
                .decommitment = .{
                    .decommitment = Decommitment{
                        .hash_witness = hash_witness_owned,
                    },
                    .aux = .{
                        .all_node_values = all_node_values_owned,
                    },
                },
            };
        }

        const ColumnRef = struct {
            values: []const M31,
            log_size: u32,
            original_index: usize,
        };

        fn sortColumnsByLogSizeAsc(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) ![]ColumnRef {
            const out = try allocator.alloc(ColumnRef, columns.len);
            for (columns, 0..) |column, i| {
                if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
                    return error.InvalidColumnSize;
                }
                out[i] = .{
                    .values = column,
                    .log_size = @intCast(std.math.log2_int(usize, column.len)),
                    .original_index = i,
                };
            }
            std.sort.heap(ColumnRef, out, {}, lessByLogSizeAscStable);
            return out;
        }

        fn lessByLogSizeAscStable(_: void, lhs: ColumnRef, rhs: ColumnRef) bool {
            if (lhs.log_size == rhs.log_size) return lhs.original_index < rhs.original_index;
            return lhs.log_size < rhs.log_size;
        }

        fn buildLeaves(
            allocator: std.mem.Allocator,
            sorted_columns: []const ColumnRef,
        ) ![]H.Hash {
            var seed_hasher = H.defaultWithInitialState();
            if (sorted_columns.len == 0) {
                const layer = try allocator.alloc(H.Hash, 1);
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
                var idx: usize = 0;
                while (idx < layer_size) : (idx += 1) {
                    for (group_columns) |column| {
                        prev_layer[idx].updateLeaf(column.values[idx .. idx + 1]);
                    }
                }

                prev_layer_log_size = log_size;
                group_start = group_end;
            }

            const out = try allocator.alloc(H.Hash, prev_layer.len);
            for (prev_layer, 0..) |*hasher, i| out[i] = hasher.finalize();
            allocator.free(prev_layer);
            return out;
        }

        fn buildNextLayer(
            allocator: std.mem.Allocator,
            prev_layer: []const H.Hash,
            executor: *LayerExecutor,
            worker_override: ?usize,
        ) ![]H.Hash {
            std.debug.assert(prev_layer.len > 1 and std.math.isPowerOfTwo(prev_layer.len));
            const out = try allocator.alloc(H.Hash, prev_layer.len >> 1);
            const workers = parallelWorkersForLayer(out.len, worker_override);

            if (workers > 1 and executor.enabled) {
                if (comptime @hasDecl(H, "nodeSeed") and @hasDecl(H, "hashChildrenWithSeed")) {
                    const seed = H.nodeSeed();
                    if (buildNextLayerSeededParallel(out, prev_layer, seed, workers, executor)) |_| {
                        return out;
                    } else |_| {}
                } else {
                    if (buildNextLayerBasicParallel(out, prev_layer, workers, executor)) |_| {
                        return out;
                    } else |_| {}
                }
            }

            if (comptime @hasDecl(H, "nodeSeed") and @hasDecl(H, "hashChildrenWithSeed")) {
                const seed = H.nodeSeed();
                var i_seeded: usize = 0;
                while (i_seeded + 4 <= out.len) : (i_seeded += 4) {
                    out[i_seeded] = H.hashChildrenWithSeed(seed, .{
                        .left = prev_layer[2 * i_seeded],
                        .right = prev_layer[2 * i_seeded + 1],
                    });
                    out[i_seeded + 1] = H.hashChildrenWithSeed(seed, .{
                        .left = prev_layer[2 * (i_seeded + 1)],
                        .right = prev_layer[2 * (i_seeded + 1) + 1],
                    });
                    out[i_seeded + 2] = H.hashChildrenWithSeed(seed, .{
                        .left = prev_layer[2 * (i_seeded + 2)],
                        .right = prev_layer[2 * (i_seeded + 2) + 1],
                    });
                    out[i_seeded + 3] = H.hashChildrenWithSeed(seed, .{
                        .left = prev_layer[2 * (i_seeded + 3)],
                        .right = prev_layer[2 * (i_seeded + 3) + 1],
                    });
                }
                while (i_seeded < out.len) : (i_seeded += 1) {
                    out[i_seeded] = H.hashChildrenWithSeed(seed, .{
                        .left = prev_layer[2 * i_seeded],
                        .right = prev_layer[2 * i_seeded + 1],
                    });
                }
                return out;
            }

            var i: usize = 0;
            while (i + 4 <= out.len) : (i += 4) {
                out[i] = H.hashChildren(.{
                    .left = prev_layer[2 * i],
                    .right = prev_layer[2 * i + 1],
                });
                out[i + 1] = H.hashChildren(.{
                    .left = prev_layer[2 * (i + 1)],
                    .right = prev_layer[2 * (i + 1) + 1],
                });
                out[i + 2] = H.hashChildren(.{
                    .left = prev_layer[2 * (i + 2)],
                    .right = prev_layer[2 * (i + 2) + 1],
                });
                out[i + 3] = H.hashChildren(.{
                    .left = prev_layer[2 * (i + 3)],
                    .right = prev_layer[2 * (i + 3) + 1],
                });
            }
            while (i < out.len) : (i += 1) {
                out[i] = H.hashChildren(.{
                    .left = prev_layer[2 * i],
                    .right = prev_layer[2 * i + 1],
                });
            }
            return out;
        }

        fn parallelWorkersForLayer(out_len: usize, worker_override: ?usize) usize {
            if (builtin.single_threaded) return 1;
            if (out_len < parallel_min_nodes) return 1;
            const capacity = out_len / parallel_min_nodes_per_worker;
            if (capacity < 2) return 1;
            if (worker_override) |requested| {
                if (requested <= 1) return 1;
                return @min(@min(requested, max_parallel_workers), capacity);
            }
            const cpu_count_raw = std.Thread.getCpuCount() catch return 1;
            const cpu_count: usize = @intCast(cpu_count_raw);
            if (cpu_count <= 1) return 1;
            return @min(@min(cpu_count, capacity), max_parallel_workers);
        }

        const SeededRangeCtx = struct {
            out: []H.Hash,
            prev_layer: []const H.Hash,
            start: usize,
            end: usize,
            seed: H,
        };

        fn hashSeededRange(ctx: *const SeededRangeCtx) void {
            var i = ctx.start;
            while (i < ctx.end) : (i += 1) {
                ctx.out[i] = H.hashChildrenWithSeed(ctx.seed, .{
                    .left = ctx.prev_layer[2 * i],
                    .right = ctx.prev_layer[2 * i + 1],
                });
            }
        }

        fn hashSeededRangeThread(ctx: *const SeededRangeCtx) void {
            hashSeededRange(ctx);
        }

        fn buildNextLayerSeededParallel(
            out: []H.Hash,
            prev_layer: []const H.Hash,
            seed: H,
            worker_count: usize,
            executor: *LayerExecutor,
        ) !void {
            std.debug.assert(worker_count > 1);
            std.debug.assert(worker_count <= max_parallel_workers);
            std.debug.assert(executor.enabled);
            var contexts: [max_parallel_workers]SeededRangeCtx = undefined;

            const chunk_len = (out.len + worker_count - 1) / worker_count;
            var actual_workers: usize = 0;
            var start: usize = 0;
            while (start < out.len and actual_workers < worker_count) : (actual_workers += 1) {
                const end = @min(out.len, start + chunk_len);
                contexts[actual_workers] = SeededRangeCtx{
                    .out = out,
                    .prev_layer = prev_layer,
                    .start = start,
                    .end = end,
                    .seed = seed,
                };
                start = end;
            }
            if (actual_workers <= 1) {
                hashSeededRange(&contexts[0]);
                return;
            }

            var wait_group: WaitGroup = .{};
            for (1..actual_workers) |i| {
                executor.pool.spawnWg(&wait_group, hashSeededRangeThread, .{&contexts[i]});
            }
            hashSeededRange(&contexts[0]);
            wait_group.wait();
        }

        const BasicRangeCtx = struct {
            out: []H.Hash,
            prev_layer: []const H.Hash,
            start: usize,
            end: usize,
        };

        fn hashBasicRange(ctx: *const BasicRangeCtx) void {
            var i = ctx.start;
            while (i < ctx.end) : (i += 1) {
                ctx.out[i] = H.hashChildren(.{
                    .left = ctx.prev_layer[2 * i],
                    .right = ctx.prev_layer[2 * i + 1],
                });
            }
        }

        fn hashBasicRangeThread(ctx: *const BasicRangeCtx) void {
            hashBasicRange(ctx);
        }

        fn buildNextLayerBasicParallel(
            out: []H.Hash,
            prev_layer: []const H.Hash,
            worker_count: usize,
            executor: *LayerExecutor,
        ) !void {
            std.debug.assert(worker_count > 1);
            std.debug.assert(worker_count <= max_parallel_workers);
            std.debug.assert(executor.enabled);
            var contexts: [max_parallel_workers]BasicRangeCtx = undefined;

            const chunk_len = (out.len + worker_count - 1) / worker_count;
            var actual_workers: usize = 0;
            var start: usize = 0;
            while (start < out.len and actual_workers < worker_count) : (actual_workers += 1) {
                const end = @min(out.len, start + chunk_len);
                contexts[actual_workers] = BasicRangeCtx{
                    .out = out,
                    .prev_layer = prev_layer,
                    .start = start,
                    .end = end,
                };
                start = end;
            }
            if (actual_workers <= 1) {
                hashBasicRange(&contexts[0]);
                return;
            }

            var wait_group: WaitGroup = .{};
            for (1..actual_workers) |i| {
                executor.pool.spawnWg(&wait_group, hashBasicRangeThread, .{&contexts[i]});
            }
            hashBasicRange(&contexts[0]);
            wait_group.wait();
        }
    };
}

test "prover vcs_lifted: decommit and verify roundtrip" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("../../core/vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const columns = [_][]const M31{
        &[_]M31{
            M31.fromCanonical(1),
            M31.fromCanonical(2),
            M31.fromCanonical(3),
            M31.fromCanonical(4),
            M31.fromCanonical(5),
            M31.fromCanonical(6),
            M31.fromCanonical(7),
            M31.fromCanonical(8),
        },
        &[_]M31{
            M31.fromCanonical(9),
            M31.fromCanonical(10),
            M31.fromCanonical(11),
            M31.fromCanonical(12),
        },
        &[_]M31{
            M31.fromCanonical(13),
            M31.fromCanonical(14),
            M31.fromCanonical(15),
            M31.fromCanonical(16),
            M31.fromCanonical(17),
            M31.fromCanonical(18),
            M31.fromCanonical(19),
            M31.fromCanonical(20),
        },
    };

    var prover = try Prover.commit(alloc, columns[0..]);
    defer prover.deinit(alloc);

    const query_positions = [_]usize{ 1, 6 };
    var decommitment = try prover.decommit(alloc, query_positions[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
    defer alloc.free(queried_values);
    for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

    var verifier = try Verifier.init(alloc, prover.root(), &[_]u32{ 3, 2, 3 });
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        query_positions[0..],
        queried_values,
        decommitment.decommitment.decommitment,
    );
}

test "prover vcs_lifted: invalid witness fails verification" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("../../core/vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const columns = [_][]const M31{
        &[_]M31{
            M31.fromCanonical(1),
            M31.fromCanonical(2),
            M31.fromCanonical(3),
            M31.fromCanonical(4),
        },
    };

    var prover = try Prover.commit(alloc, columns[0..]);
    defer prover.deinit(alloc);

    const query_positions = [_]usize{1};
    var decommitment = try prover.decommit(alloc, query_positions[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    decommitment.decommitment.decommitment.hash_witness[0][0] ^= 1;

    const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
    defer alloc.free(queried_values);
    for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

    var verifier = try Verifier.init(alloc, prover.root(), &[_]u32{2});
    defer verifier.deinit(alloc);
    try std.testing.expectError(
        vcs_lifted_verifier.MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            query_positions[0..],
            queried_values,
            decommitment.decommitment.decommitment,
        ),
    );
}

test "prover vcs_lifted: empty columns root matches mixed-degree prover" {
    const LiftedHasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MixedHasher = @import("../../core/vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = MerkleProverLifted(LiftedHasher);
    const MixedProver = @import("../vcs/prover.zig").MerkleProver(MixedHasher);
    const alloc = std.testing.allocator;

    const no_columns = [_][]const M31{};
    var lifted = try LiftedProver.commit(alloc, no_columns[0..]);
    defer lifted.deinit(alloc);
    var mixed = try MixedProver.commit(alloc, no_columns[0..]);
    defer mixed.deinit(alloc);

    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&lifted.root()), std.mem.asBytes(&mixed.root())));
}

test "prover vcs_lifted: root is stable across large-layer worker-count overrides" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;
    const log_size: u32 = 14;
    const n = @as(usize, 1) << @intCast(log_size);

    var col0 = try alloc.alloc(M31, n);
    defer alloc.free(col0);
    var col1 = try alloc.alloc(M31, n);
    defer alloc.free(col1);

    for (0..n) |i| {
        col0[i] = M31.fromU64(@as(u64, @intCast(i + 1)));
        col1[i] = M31.fromU64(@as(u64, @intCast((i * 17) + 3)));
    }

    const columns = [_][]const M31{
        col0,
        col1,
    };

    var prover_auto = try Prover.commitWithWorkerOverride(alloc, columns[0..], null);
    defer prover_auto.deinit(alloc);
    var prover_single = try Prover.commitWithWorkerOverride(alloc, columns[0..], 1);
    defer prover_single.deinit(alloc);
    var prover_two = try Prover.commitWithWorkerOverride(alloc, columns[0..], 2);
    defer prover_two.deinit(alloc);
    var prover_four = try Prover.commitWithWorkerOverride(alloc, columns[0..], 4);
    defer prover_four.deinit(alloc);

    const root_auto = prover_auto.root();
    const root_single = prover_single.root();
    const root_two = prover_two.root();
    const root_four = prover_four.root();
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&root_auto), std.mem.asBytes(&root_single)));
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&root_auto), std.mem.asBytes(&root_two)));
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&root_auto), std.mem.asBytes(&root_four)));
}
