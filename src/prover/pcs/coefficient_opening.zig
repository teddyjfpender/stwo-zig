//! Selective openings from coefficient-backed host commitments. Scratch is one
//! bounded LDE batch plus queried leaf blocks, independent of commitment width.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const poly = @import("../poly/circle/mod.zig");
const twiddles = @import("../poly/twiddles.zig");
const work_pool = @import("../work_pool.zig");
const Column = @import("stwo_prover_api").ColumnEvaluation;
const batch_byte_limit = 128 * 1024 * 1024;
const traversal = @import("../vcs_lifted/decommit.zig");

pub fn decommit(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
    const max_log = tree.commitment.maxLogSize();
    const size = @as(usize, 1) << @intCast(max_log);
    for (queries, 0..) |query, i| {
        if (query >= size or (i != 0 and query < queries[i - 1])) return error.InvalidColumnSize;
    }
    var first_missing: usize = tree.commitment.layers.len;
    for (tree.commitment.layers, 0..) |layer, i| if (layer.len == 0) {
        first_missing = i;
        break;
    };
    var leaves = std.ArrayList(usize).empty;
    defer leaves.deinit(a);
    if (first_missing < tree.commitment.layers.len) {
        if (first_missing == 0) return error.InvalidColumnSize;
        const block_size = @as(usize, 1) << @intCast(tree.commitment.layers.len - first_missing);
        for (queries) |query| {
            const start = query & ~(block_size - 1);
            if (leaves.items.len != 0 and leaves.items[leaves.items.len - 1] >= start) continue;
            try leaves.ensureUnusedCapacity(a, block_size);
            for (start..start + block_size) |position| leaves.appendAssumeCapacity(position);
        }
    }
    const hashers = try a.alloc(H, leaves.items.len);
    defer a.free(hashers);
    for (hashers) |*hasher| hasher.* = H.defaultWithInitialState();
    const values = try a.alloc([]M31, tree.columns.len);
    var initialized: usize = 0;
    defer {
        for (values[0..initialized]) |column| a.free(column);
        a.free(values);
    }
    for (values) |*column| {
        column.* = try a.alloc(M31, queries.len);
        initialized += 1;
    }
    const indices = try a.alloc(usize, tree.columns.len);
    defer a.free(indices);
    for (indices, 0..) |*index, i| index.* = i;
    const Order = struct {
        columns: @TypeOf(tree.columns),
        fn less(self: @This(), left: usize, right: usize) bool {
            const x = self.columns[left].log_size;
            const y = self.columns[right].log_size;
            return x < y or (x == y and left < right);
        }
    };
    std.sort.heap(usize, indices, Order{ .columns = tree.columns }, Order.less);
    var transform = try twiddles.precomputeM31(a, poly.CanonicCoset.new(max_log).circleDomain().half_coset);
    defer twiddles.deinitM31(a, &transform);
    const pool = work_pool.getGlobalPool();
    const worker_count = if (pool) |active| active.workerCount() else 1;
    var next: usize = 0;
    while (next < indices.len) {
        var end = next;
        var bytes: usize = 0;
        while (end < indices.len and end - next < worker_count) : (end += 1) {
            const column = tree.columns[indices[end]];
            try column.validateRetained();
            if (column.log_size > max_log) return error.InvalidColumnSize;
            const required = if (column.coefficient_values != null)
                try std.math.mul(usize, @as(usize, 1) << @intCast(column.log_size), @sizeOf(M31))
            else
                0;
            if (end != next and try std.math.add(usize, bytes, required) > batch_byte_limit) break;
            bytes = try std.math.add(usize, bytes, required);
        }
        var jobs: [work_pool.MAX_WORKERS]Expansion = undefined;
        var initialized_jobs: usize = 0;
        defer for (jobs[0..initialized_jobs]) |job| if (job.column.coefficient_values != null) a.free(job.values);
        for (indices[next..end], jobs[0 .. end - next]) |index, *job| {
            const column = tree.columns[index];
            job.* = .{ .column = column, .values = if (column.coefficient_values != null)
                try a.alloc(M31, @as(usize, 1) << @intCast(column.log_size))
            else
                @constCast(column.values), .transform = .{ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles } };
            initialized_jobs += 1;
        }
        if (pool) |active| {
            var group: std.Thread.WaitGroup = .{};
            for (jobs[1..initialized_jobs]) |*job| active.spawnWg(&group, Expansion.run, .{job});
            jobs[0].run();
            group.wait();
        } else jobs[0].run();
        for (jobs[0..initialized_jobs]) |job| if (job.failure) |failure| return failure;
        // FFTs write disjoint columns. Leaf absorption remains in canonical
        // column order after the bounded worker wave has joined.
        for (indices[next..end], jobs[0..initialized_jobs]) |index, job| {
            const shift: std.math.Log2Int(usize) = @intCast(max_log - job.column.log_size + 1);
            for (queries, values[index]) |position, *value| value.* = job.values[((position >> shift) << 1) + (position & 1)];
            for (leaves.items, hashers) |position, *hasher| {
                const at = ((position >> shift) << 1) + (position & 1);
                hasher.updateLeaf(job.values[at..][0..1]);
            }
        }
        next = end;
    }
    const hashes = try a.alloc(H.Hash, hashers.len);
    defer a.free(hashes);
    for (hashers, hashes) |*hasher, *hash| hash.* = hasher.finalize();
    const Reader = struct {
        commitment: @TypeOf(tree.commitment),
        positions: []const usize,
        hashes: []const H.Hash,
        values: []const []M31,
        pub fn maxLogSize(self: @This()) u32 {
            return self.commitment.maxLogSize();
        }
        pub fn readQueriedValuesBatch(self: @This(), allocator: std.mem.Allocator, _: []const usize, _: []const []const M31) !?[][]M31 {
            const out = try allocator.alloc([]M31, self.values.len);
            var count: usize = 0;
            errdefer {
                for (out[0..count]) |column| allocator.free(column);
                allocator.free(out);
            }
            for (self.values, out) |source, *destination| {
                destination.* = try allocator.dupe(M31, source);
                count += 1;
            }
            return out;
        }
        fn node(self: @This(), layer: u32, index: usize) !H.Hash {
            if (layer > self.maxLogSize() or index >= @as(usize, 1) << @intCast(layer)) return error.InvalidColumnSize;
            if (self.commitment.layers[layer].len != 0) return self.commitment.layers[layer][index];
            if (layer == self.maxLogSize()) {
                var low: usize = 0;
                var high = self.positions.len;
                while (low < high) {
                    const mid = low + (high - low) / 2;
                    if (self.positions[mid] < index) low = mid + 1 else high = mid;
                }
                if (low == self.positions.len or self.positions[low] != index) return error.InvalidColumnSize;
                return self.hashes[low];
            }
            return H.hashChildren(.{ .left = try self.node(layer + 1, index * 2), .right = try self.node(layer + 1, index * 2 + 1) });
        }
        pub fn readHashes(self: @This(), allocator: std.mem.Allocator, layer: u32, positions: []const u32) ![]H.Hash {
            const out = try allocator.alloc(H.Hash, positions.len);
            errdefer allocator.free(out);
            for (positions, out) |position, *hash| hash.* = try self.node(layer, position);
            return out;
        }
    };
    return traversal.decommit(H, Reader{ .commitment = tree.commitment, .positions = leaves.items, .hashes = hashes, .values = values }, a, queries, &.{});
}

const Expansion = struct {
    column: Column,
    values: []M31,
    transform: twiddles.TwiddleTree([]const M31),
    failure: ?anyerror = null,
    fn run(self: *@This()) void {
        self.evaluate() catch |err| {
            self.failure = err;
        };
    }
    fn evaluate(self: *@This()) !void {
        const coefficients = self.column.coefficient_values orelse return;
        const domain = poly.CanonicCoset.new(self.column.log_size).circleDomain();
        @memcpy(self.values[0..coefficients.len], coefficients);
        if (coefficients.len * 2 == self.values.len) {
            try poly.poly.evaluateExtensionBuffersWithTwiddles(&.{self.values}, domain, self.transform);
        } else {
            @memset(self.values[coefficients.len..], M31.zero());
            try poly.poly.evaluateBuffersWithTwiddles(&.{self.values}, domain, self.transform);
        }
    }
};
