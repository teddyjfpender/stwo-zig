//! Selective openings from coefficient-backed host commitments. Scratch is one
//! bounded coefficient-window batch plus queried leaf blocks, independent of
//! commitment width.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const poly = @import("../poly/circle/mod.zig");
const twiddles = @import("../poly/twiddles.zig");
const work_pool = @import("../work_pool.zig");
const Column = @import("stwo_prover_api").ColumnEvaluation;
const batch_byte_limit = 128 * 1024 * 1024;
const traversal = @import("../vcs_lifted/decommit.zig");
const transforms = @import("../poly/circle/transforms.zig");

pub fn decommit(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
    return decommitForBackend(void, H, a, tree, queries);
}

/// Host openings default to coefficient-sized pruned windows with per-worker
/// scratch reuse and a column work queue. STWO_ZIG_FULL_SCRATCH_OPENING=1
/// restores the previous full-scratch wave schedule for A/B comparison.
pub fn decommitForBackend(comptime B: type, comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
    const native_expansion = comptime B != void and @hasDecl(B, "evaluateCircleBuffers");
    if (native_expansion or std.process.hasEnvVarConstant("STWO_ZIG_FULL_SCRATCH_OPENING"))
        return decommitWaves(B, H, a, tree, queries, false);
    return decommitQueued(H, a, tree, queries, true);
}

fn validateQueries(max_log: u32, queries: []const usize) !void {
    const size = @as(usize, 1) << @intCast(max_log);
    for (queries, 0..) |query, i| {
        if (query >= size or (i != 0 and query < queries[i - 1])) return error.InvalidColumnSize;
    }
}

/// Leaf positions whose hashes must be recomputed (sorted, unique).
fn collectLeaves(a: std.mem.Allocator, tree: anytype, queries: []const usize) !std.ArrayList(usize) {
    var leaves = std.ArrayList(usize).empty;
    errdefer leaves.deinit(a);
    var first_missing: usize = tree.commitment.layers.len;
    for (tree.commitment.layers, 0..) |layer, i| if (layer.len == 0) {
        first_missing = i;
        break;
    };
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
    return leaves;
}

fn sortedColumnOrder(a: std.mem.Allocator, columns: anytype) ![]usize {
    const indices = try a.alloc(usize, columns.len);
    for (indices, 0..) |*index, i| index.* = i;
    const Order = struct {
        columns: @TypeOf(columns),
        fn less(self: @This(), left: usize, right: usize) bool {
            const x = self.columns[left].log_size;
            const y = self.columns[right].log_size;
            return x < y or (x == y and left < right);
        }
    };
    std.sort.heap(usize, indices, Order{ .columns = columns }, Order.less);
    return indices;
}

fn allocValues(a: std.mem.Allocator, columns: usize, queries: usize) ![][]M31 {
    const values = try a.alloc([]M31, columns);
    var initialized: usize = 0;
    errdefer {
        for (values[0..initialized]) |column| a.free(column);
        a.free(values);
    }
    for (values) |*column| {
        column.* = try a.alloc(M31, queries);
        initialized += 1;
    }
    return values;
}

fn freeValues(a: std.mem.Allocator, values: [][]M31) void {
    for (values) |column| a.free(column);
    a.free(values);
}

inline fn project(position: usize, shift: std.math.Log2Int(usize)) usize {
    return ((position >> shift) << 1) + (position & 1);
}

/// Work-queue opening: every coefficient-backed column is expanded by whichever
/// worker is free next into that worker's reusable scratch; the selected
/// evaluations land in a per-column slot. Leaf absorption then runs serially in
/// canonical (log size, index) order, so hashes are schedule independent.
fn decommitQueued(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize, half: bool) !traversal.DecommitmentResult(H) {
    const max_log = tree.commitment.maxLogSize();
    try validateQueries(max_log, queries);
    var leaves = try collectLeaves(a, tree, queries);
    defer leaves.deinit(a);
    const columns = tree.columns;
    for (columns) |column| {
        try column.validateRetained();
        if (column.log_size > max_log) return error.InvalidColumnSize;
    }
    const plans = try a.alloc(?PositionPlan, max_log + 1);
    @memset(plans, null);
    defer {
        for (plans) |*plan| if (plan.*) |*value| value.deinit(a);
        a.free(plans);
    }
    const offsets = try a.alloc(usize, columns.len);
    defer a.free(offsets);
    var work = std.ArrayList(usize).empty;
    defer work.deinit(a);
    var selected_len: usize = 0;
    var max_scratch: usize = 0;
    for (columns, offsets, 0..) |column, *offset, i| {
        offset.* = selected_len;
        if (column.coefficient_values == null) continue;
        if (plans[column.log_size] == null) plans[column.log_size] = try PositionPlan.init(a, max_log, column.log_size, queries, leaves.items);
        selected_len = try std.math.add(usize, selected_len, plans[column.log_size].?.positions.len);
        max_scratch = @max(max_scratch, scratchLength(column, half));
        try work.append(a, i);
    }
    const selected = try a.alloc(M31, selected_len);
    defer a.free(selected);
    // Largest columns first keeps the queue tail short.
    const Largest = struct {
        columns: @TypeOf(columns),
        fn less(self: @This(), left: usize, right: usize) bool {
            const x = self.columns[left].log_size;
            const y = self.columns[right].log_size;
            return x > y or (x == y and left < right);
        }
    };
    std.sort.heap(usize, work.items, Largest{ .columns = columns }, Largest.less);
    if (work.items.len != 0) {
        var transform = try twiddles.precomputeM31(a, poly.CanonicCoset.new(max_log).circleDomain().half_coset);
        defer twiddles.deinitM31(a, &transform);
        const pool = work_pool.getGlobalPool();
        const scratch_bytes = try std.math.mul(usize, max_scratch, @sizeOf(M31));
        const budget_workers = @max(1, batch_byte_limit / scratch_bytes);
        const workers = @min(@min(if (pool) |active| active.workerCount() else 1, budget_workers), @min(work.items.len, work_pool.MAX_WORKERS));
        const scratch = try a.alloc(M31, try std.math.mul(usize, max_scratch, workers));
        defer a.free(scratch);
        var queue: Queue(@TypeOf(columns)) = .{
            .columns = columns,
            .work = work.items,
            .plans = plans,
            .offsets = offsets,
            .selected = selected,
            .scratch = scratch,
            .scratch_len = max_scratch,
            .half = half,
            .transform = .{ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles },
        };
        if (pool != null and workers > 1) {
            var group: std.Thread.WaitGroup = .{};
            for (1..workers) |worker| pool.?.spawnWg(&group, @TypeOf(queue).run, .{ &queue, worker });
            queue.run(0);
            group.wait();
        } else queue.run(0);
        for (queue.failures[0..workers]) |failure| if (failure) |err| return err;
    }
    const hashers = try a.alloc(H, leaves.items.len);
    defer a.free(hashers);
    for (hashers) |*hasher| hasher.* = H.defaultWithInitialState();
    const values = try allocValues(a, columns.len, queries.len);
    defer freeValues(a, values);
    const indices = try sortedColumnOrder(a, columns);
    defer a.free(indices);
    for (indices) |index| {
        const column = columns[index];
        const shift: std.math.Log2Int(usize) = @intCast(max_log - column.log_size + 1);
        if (column.coefficient_values != null) {
            const plan = &plans[column.log_size].?;
            const source = selected[offsets[index]..][0..plan.positions.len];
            for (plan.query_indices, values[index]) |at, *value| value.* = source[at];
            for (plan.leaf_indices, hashers) |at, *hasher| hasher.updateLeaf(source[at..][0..1]);
        } else {
            for (queries, values[index]) |position, *value| value.* = column.values[project(position, shift)];
            for (leaves.items, hashers) |position, *hasher| hasher.updateLeaf(column.values[project(position, shift)..][0..1]);
        }
    }
    return finish(H, a, tree, queries, leaves.items, hashers, values);
}

fn Queue(comptime Columns: type) type {
    return struct {
        columns: Columns,
        work: []const usize,
        plans: []const ?PositionPlan,
        offsets: []const usize,
        selected: []M31,
        scratch: []M31,
        scratch_len: usize,
        half: bool,
        transform: twiddles.TwiddleTree([]const M31),
        next: std.atomic.Value(usize) = .init(0),
        stop: std.atomic.Value(bool) = .init(false),
        failures: [work_pool.MAX_WORKERS]?anyerror = @splat(null),

        fn run(self: *@This(), worker: usize) void {
            const scratch = self.scratch[worker * self.scratch_len ..][0..self.scratch_len];
            while (!self.stop.load(.monotonic)) {
                const item = self.next.fetchAdd(1, .monotonic);
                if (item >= self.work.len) return;
                self.expand(self.work[item], scratch) catch |err| {
                    self.failures[worker] = err;
                    self.stop.store(true, .monotonic);
                    return;
                };
            }
        }

        fn expand(self: *@This(), index: usize, scratch: []M31) !void {
            const column = self.columns[index];
            const coefficients = column.coefficient_values.?;
            const plan = &self.plans[column.log_size].?;
            const out = self.selected[self.offsets[index]..][0..plan.positions.len];
            const domain = poly.CanonicCoset.new(column.log_size).circleDomain();
            const values = scratch[0..scratchLength(column, self.half)];
            if (self.half) return transforms.evaluateSelectedCoefficientsWithTwiddles(coefficients, values, domain, self.transform, plan.positions, out);
            @memcpy(values[0..coefficients.len], coefficients);
            try transforms.evaluateSelectedBufferWithTwiddles(values, coefficients.len, domain, self.transform, plan.positions);
            for (plan.positions, out) |position, *value| value.* = values[position];
        }
    };
}

/// Previous schedule: bounded waves with a fresh scratch per column. Kept for
/// native (GPU) expansion and as the STWO_ZIG_FULL_SCRATCH_OPENING A/B path.
fn decommitWaves(comptime B: type, comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize, half_requested: bool) !traversal.DecommitmentResult(H) {
    const native_expansion = comptime B != void and @hasDecl(B, "evaluateCircleBuffers");
    const use_half = !native_expansion and half_requested;
    const max_log = tree.commitment.maxLogSize();
    try validateQueries(max_log, queries);
    var leaves = try collectLeaves(a, tree, queries);
    defer leaves.deinit(a);
    const plans: []?PositionPlan = if (use_half) try a.alloc(?PositionPlan, max_log + 1) else &.{};
    @memset(plans, null);
    defer {
        for (plans) |*plan| if (plan.*) |*value| value.deinit(a);
        a.free(plans);
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
                try std.math.mul(usize, scratchLength(column, use_half), @sizeOf(M31))
            else
                0;
            if (end != next and try std.math.add(usize, bytes, required) > batch_byte_limit) break;
            bytes = try std.math.add(usize, bytes, required);
        }
        var jobs: [work_pool.MAX_WORKERS]Expansion = undefined;
        var native_owners: [work_pool.MAX_WORKERS][]align(std.heap.page_size_max) M31 = undefined;
        var native_owner_count: usize = 0;
        defer for (native_owners[0..native_owner_count]) |owner| a.free(owner);
        var initialized_jobs: usize = 0;
        defer for (jobs[0..initialized_jobs]) |job| {
            if (!native_expansion and job.column.coefficient_values != null) a.free(job.values);
            a.free(job.positions);
            a.free(job.selected);
        };
        for (indices[next..end], jobs[0 .. end - next]) |index, *job| {
            const column = tree.columns[index];
            const positions = if (!use_half and !native_expansion and column.coefficient_values != null) blk: {
                const out = try a.alloc(usize, try std.math.add(usize, queries.len, leaves.items.len));
                const shift: std.math.Log2Int(usize) = @intCast(max_log - column.log_size + 1);
                for (queries, out[0..queries.len]) |position, *target| target.* = ((position >> shift) << 1) + (position & 1);
                for (leaves.items, out[queries.len..]) |position, *target| target.* = ((position >> shift) << 1) + (position & 1);
                std.sort.heap(usize, out, {}, std.sort.asc(usize));
                break :blk out;
            } else &.{};
            errdefer a.free(positions);
            const plan: ?*const PositionPlan = if (use_half and column.coefficient_values != null) blk: {
                if (plans[column.log_size] == null) plans[column.log_size] = try PositionPlan.init(a, max_log, column.log_size, queries, leaves.items);
                break :blk &plans[column.log_size].?;
            } else null;
            const scratch: []M31 = if (column.coefficient_values != null)
                if (native_expansion) &.{} else try a.alloc(M31, scratchLength(column, use_half))
            else
                @constCast(column.values);
            errdefer if (!native_expansion and column.coefficient_values != null) a.free(scratch);
            const selected: []M31 = if (plan) |p| try a.alloc(M31, p.positions.len) else &.{};
            job.* = .{ .column = column, .positions = positions, .values = scratch, .selected = selected, .plan = plan, .transform = .{ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles } };
            initialized_jobs += 1;
        }
        if (native_expansion) {
            var first: usize = 0;
            while (first < initialized_jobs) {
                if (jobs[first].column.coefficient_values == null) {
                    first += 1;
                    continue;
                }
                const log = jobs[first].column.log_size;
                var last = first + 1;
                while (last < initialized_jobs and jobs[last].column.log_size == log) : (last += 1) {}
                var count: usize = 0;
                for (jobs[first..last]) |job| if (job.column.coefficient_values != null) {
                    count += 1;
                };
                const rows = @as(usize, 1) << @intCast(log);
                const owner = try a.alignedAlloc(M31, comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max), try std.math.mul(usize, rows, count));
                native_owners[native_owner_count] = owner;
                native_owner_count += 1;
                var buffers: [work_pool.MAX_WORKERS][]M31 = undefined;
                count = 0;
                for (jobs[first..last]) |*job| {
                    const coefficients = job.column.coefficient_values orelse continue;
                    job.values = owner[count * rows ..][0..rows];
                    @memcpy(job.values[0..coefficients.len], coefficients);
                    @memset(job.values[coefficients.len..], M31.zero());
                    buffers[count] = job.values;
                    count += 1;
                }
                _ = try B.evaluateCircleBuffers(a, buffers[0..count], poly.CanonicCoset.new(log).circleDomain(), try jobs[first].transform.subtree(log - 1));
                first = last;
            }
        } else if (pool) |active| {
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
            for (queries, values[index], 0..) |position, *value, i| value.* = if (job.plan) |plan|
                job.selected[plan.query_indices[i]]
            else
                job.values[((position >> shift) << 1) + (position & 1)];
            for (leaves.items, hashers, 0..) |position, *hasher, i| {
                const source = if (job.plan) |plan| job.selected[plan.leaf_indices[i]..][0..1] else blk: {
                    const at = ((position >> shift) << 1) + (position & 1);
                    break :blk job.values[at..][0..1];
                };
                hasher.updateLeaf(source);
            }
        }
        next = end;
    }
    return finish(H, a, tree, queries, leaves.items, hashers, values);
}

fn finish(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize, leaves: []const usize, hashers: []H, values: []const []M31) !traversal.DecommitmentResult(H) {
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
    return traversal.decommit(H, Reader{ .commitment = tree.commitment, .positions = leaves, .hashes = hashes, .values = values }, a, queries, &.{});
}

const Expansion = struct {
    column: Column,
    values: []M31,
    transform: twiddles.TwiddleTree([]const M31),
    positions: []const usize,
    selected: []M31,
    plan: ?*const PositionPlan,
    failure: ?anyerror = null,
    fn run(self: *@This()) void {
        self.evaluate() catch |err| {
            self.failure = err;
        };
    }
    fn evaluate(self: *@This()) !void {
        const coefficients = self.column.coefficient_values orelse return;
        const domain = poly.CanonicCoset.new(self.column.log_size).circleDomain();
        if (self.plan) |plan| return @import("../poly/circle/transforms.zig").evaluateSelectedCoefficientsWithTwiddles(coefficients, self.values, domain, self.transform, plan.positions, self.selected);
        @memcpy(self.values[0..coefficients.len], coefficients);
        try @import("../poly/circle/transforms.zig").evaluateSelectedBufferWithTwiddles(
            self.values,
            coefficients.len,
            domain,
            self.transform,
            self.positions,
        );
    }
};

fn scratchLength(column: Column, half: bool) usize {
    const n = @as(usize, 1) << @intCast(column.log_size);
    return if (half) transforms.selectedCoefficientScratchLength(column.coefficient_values.?.len, column.log_size) else n;
}

/// Project and canonicalize once per native height, not once per column.
const PositionPlan = struct {
    storage: []usize,
    positions: []const usize,
    query_indices: []usize,
    leaf_indices: []usize,
    fn init(a: std.mem.Allocator, max_log: u32, log: u32, queries: []const usize, leaves: []const usize) !PositionPlan {
        const shift: std.math.Log2Int(usize) = @intCast(max_log - log + 1);
        const storage = try a.alloc(usize, try std.math.add(usize, queries.len, leaves.len));
        errdefer a.free(storage);
        for (queries, storage[0..queries.len]) |position, *out| out.* = ((position >> shift) << 1) + (position & 1);
        for (leaves, storage[queries.len..]) |position, *out| out.* = ((position >> shift) << 1) + (position & 1);
        std.sort.heap(usize, storage, {}, std.sort.asc(usize));
        var count: usize = 0;
        for (storage) |position| if (count == 0 or storage[count - 1] != position) {
            storage[count] = position;
            count += 1;
        };
        const positions = storage[0..count];
        const query_indices = try a.alloc(usize, queries.len);
        errdefer a.free(query_indices);
        const leaf_indices = try a.alloc(usize, leaves.len);
        errdefer a.free(leaf_indices);
        for (queries, query_indices) |position, *out| out.* = locate(positions, ((position >> shift) << 1) + (position & 1));
        for (leaves, leaf_indices) |position, *out| out.* = locate(positions, ((position >> shift) << 1) + (position & 1));
        return .{ .storage = storage, .positions = positions, .query_indices = query_indices, .leaf_indices = leaf_indices };
    }
    fn locate(positions: []const usize, value: usize) usize {
        var low: usize = 0;
        var high = positions.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (positions[mid] < value) low = mid + 1 else high = mid;
        }
        std.debug.assert(low < positions.len and positions[low] == value);
        return low;
    }
    fn deinit(self: *PositionPlan, a: std.mem.Allocator) void {
        a.free(self.storage);
        a.free(self.query_indices);
        a.free(self.leaf_indices);
        self.* = undefined;
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    /// Previous default: full-scratch waves (STWO_ZIG_FULL_SCRATCH_OPENING).
    pub fn decommitFull(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
        return decommitWaves(void, H, a, tree, queries, false);
    }
    /// Current default: half-scratch work queue with per-worker scratch reuse.
    pub fn decommitHalf(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
        return decommitQueued(H, a, tree, queries, true);
    }
    /// Half-scratch waves, the previously optional mode.
    pub fn decommitHalfWaves(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
        return decommitWaves(void, H, a, tree, queries, true);
    }
    /// Full-scratch work queue with deduplicated positions.
    pub fn decommitFullQueued(comptime H: type, a: std.mem.Allocator, tree: anytype, queries: []const usize) !traversal.DecommitmentResult(H) {
        return decommitQueued(H, a, tree, queries, false);
    }
} else struct {};
