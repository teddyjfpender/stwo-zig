//! Compact mixed-height sampled evaluation through real PCS tree owners.
const std = @import("std");
const core = @import("stwo_core");
const owner = @import("sampled_values.zig");
const pools = @import("../work_pool.zig");
const poly = @import("../poly/circle/mod.zig");
const point = @import("../poly/circle/point_evaluation.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Backend = struct {
    pub fn MerkleTree(comptime Hasher: type) type {
        return @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher);
    }
    pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M) !MerkleTree(Hasher) {
        return MerkleTree(Hasher).commit(allocator, columns);
    }
};
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const Tree = @import("commitment_tree.zig").CommitmentTreeProverForBackend(Backend, H);
const Column = @import("stwo_prover_api").ColumnEvaluation;
const Point = core.circle.CirclePointQM31;
const Points = core.pcs.TreeVec([][]Point);
const a = std.testing.allocator;

test "sampled compact tree queue preserves ragged columns points zeroes and lifting under bounded and held pools" {
    const count = 103;
    const rows = 1 << 12;
    const storage = try a.alloc(M, count * rows);
    defer a.free(storage);
    for (storage, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * 17 + 31) % 127));
    @memset(storage[0..rows], M.zero());
    var columns: [count]Column = undefined;
    for (&columns, 0..) |*column, i| column.* = .{ .log_size = if (i < 68) 12 else 10, .values = storage[i * rows ..][0..if (i < 68) rows else 1024] };
    var trees = [_]Tree{ try Tree.init(a, columns[0..1]), try Tree.init(a, columns[1..68]), try Tree.init(a, columns[68..]) };
    defer for (&trees) |*tree| tree.deinit(a);
    var offset: usize = 0;
    for (&trees) |*tree| {
        const coefficients = try a.alloc(poly.CircleCoefficients, tree.columns.len);
        for (coefficients, 0..) |*c, i| c.* = try poly.CircleCoefficients.initBorrowed(columns[offset + i].values);
        tree.coefficients = coefficients;
        try tree.compactPolynomialStorage(a, 5);
        offset += tree.columns.len;
    }
    var samples = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29) };
    var column_points: [count][]Point = undefined;
    for (&column_points, 0..) |*p, i| p.* = samples[0..if (i == count - 1) 0 else if (i % 5 == 0) 1 else 2];
    var point_trees = [_][][]Point{ column_points[0..1], column_points[1..68], column_points[68..] };
    const points = Points{ .items = &point_trees };
    for ([_]usize{ 1, 2, 7 }) |threads| {
        var pool: pools.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = threads });
        defer pool.deinit();
        var binding = try pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]bool{ false, true }) |hold_pool| {
            var held: ?pools.WorkLease = if (hold_pool) try pool.acquire(try pools.WorkerBudget.init(threads)) else null;
            defer if (held) |*lease| lease.deinit();
            const available = pool.availableWorkers();
            var audit: @import("stwo_prover_api").work_profile.Recorder(true) = .{};
            const capture = threads == 2 and !hold_pool;
            var values = try owner.evaluateAndReleaseWithWorkRecorder(Backend, H, a, &trees, points, 12, if (capture) &audit else null);
            defer values.deinitDeep(a);
            if (capture) {
                try std.testing.expect(!audit.incomplete);
                try std.testing.expect(audit.counters.field_multiplications != 0);
            }
            try std.testing.expectEqual(available, pool.availableWorkers());
            for (trees, point_trees, values.items) |tree, locations, tree_values| {
                try std.testing.expect(tree.coefficients != null); // compact owner retained
                for (tree.coefficients.?, locations, tree_values) |coefficients, positions, actual| {
                    for (positions, actual) |location, value| {
                        const folded = point.repeatedDoubleOnCircleQM31(location, 12 - coefficients.logSize());
                        try std.testing.expect(coefficients.evalAtPoint(folded).eql(value));
                    }
                }
            }
        }
    }
}

test "sampled cooperative queue joins all disjoint leaf slots even when one planned item fails" {
    const Context = struct {
        active: std.atomic.Value(usize) = .init(0),
        failed: bool = false,
        done: [4]bool = @splat(false),
        output: [4][19]usize = @splat(@splat(0)),
        const Self = @This();
        const Leaf = struct {
            owner: *Self,
            item: usize,
            fn run(raw: *anyopaque, index: usize) void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                self.owner.output[self.item][index] = 7 * self.item + index + 1;
            }
        };
        fn run(raw: *anyopaque, item: usize) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            std.debug.assert(self.active.fetchAdd(1, .monotonic) == 0);
            defer _ = self.active.fetchSub(1, .monotonic);
            if (item == 2) {
                self.failed = true; // parent observes failure only after join
            } else {
                var leaf = Leaf{ .owner = self, .item = item };
                var batch = pools.cooperative.Batch{ .context = &leaf, .run = Leaf.run, .count = 19 };
                pools.cooperative.current().?.split(&batch);
            }
            self.done[item] = true;
        }
    };
    for ([_]usize{ 1, 2, 7 }) |threads| {
        var pool: pools.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = threads });
        defer pool.deinit();
        var context: Context = .{};
        @import("sampled_value_queue.zig").run(&pool, 4, 2, &context, Context.run);
        try std.testing.expect(context.failed);
        try std.testing.expectEqual(@as(usize, 0), context.active.load(.monotonic));
        try std.testing.expectEqual(threads, pool.availableWorkers());
        for (context.done) |done| try std.testing.expect(done);
        for (context.output, 0..) |values, item| for (values, 0..) |value, index| try std.testing.expectEqual(if (item == 2) @as(usize, 0) else 7 * item + index + 1, value);
    }
}
