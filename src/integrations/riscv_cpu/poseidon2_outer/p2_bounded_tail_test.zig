//! OP P2v2 hot-path qualification: exact tree bytes and packed dispatch.
const std = @import("std");
const Core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const H = Core.vcs_lifted.poseidon2_profile.Om31V2.MerkleHasher;
const M = Core.fields.m31.M31;
const Scalar = struct {
    inner: H,
    pub const Hash = H.Hash;
    pub const NodeSeed = void;
    pub fn nodeSeed() void {}
    pub fn defaultWithInitialState() @This() {
        return .{ .inner = H.defaultWithInitialState() };
    }
    pub fn updateLeaf(self: *@This(), values: []const M) void {
        self.inner.updateLeaf(values);
    }
    pub fn finalize(self: @This()) Hash {
        return self.inner.finalize();
    }
    pub fn hashChildren(children: struct { left: Hash, right: Hash }) Hash {
        return H.hashChildren(.{ .left = children.left, .right = children.right });
    }
    pub fn hashChildrenWithSeed(_: void, children: struct { left: Hash, right: Hash }) Hash {
        return hashChildren(.{ .left = children.left, .right = children.right });
    }
    // Preserve the pre-existing packed internal-node path in the scalar-tail
    // control, so the benchmark isolates bounded leaf dispatch and replay.
    pub fn hashChildrenWithSeed4(_: void, children: *const [8]Hash) [4]Hash {
        return H.hashChildrenWithSeed4({}, children);
    }
};
const Packed = struct {
    scalar: Scalar,
    var updates: std.atomic.Value(usize) = .init(0);
    var finalizations: std.atomic.Value(usize) = .init(0);
    pub const Hash = H.Hash;
    pub const NodeSeed = void;
    pub fn nodeSeed() void {}
    pub fn defaultWithInitialState() @This() {
        return .{ .scalar = Scalar.defaultWithInitialState() };
    }
    pub fn updateLeaf(self: *@This(), values: []const M) void {
        self.scalar.updateLeaf(values);
    }
    pub fn finalize(self: @This()) Hash {
        return self.scalar.finalize();
    }
    pub fn hashChildren(children: struct { left: Hash, right: Hash }) Hash {
        return Scalar.hashChildren(.{ .left = children.left, .right = children.right });
    }
    pub fn hashChildrenWithSeed(_: void, children: struct { left: Hash, right: Hash }) Hash {
        return hashChildren(.{ .left = children.left, .right = children.right });
    }
    // Preserve the pre-existing packed internal-node path in the scalar-tail
    // control, so the benchmark isolates bounded leaf dispatch and replay.
    pub fn hashChildrenWithSeed4(_: void, children: *const [8]Hash) [4]Hash {
        return H.hashChildrenWithSeed4({}, children);
    }
    pub fn updateM31Columns4(hashers: *[4]@This(), columns: anytype, position: usize) void {
        _ = updates.fetchAdd(1, .monotonic);
        var inner: [4]H = undefined;
        inline for (0..4) |lane| inner[lane] = hashers[lane].scalar.inner;
        H.updateM31Columns4(&inner, columns, position);
        inline for (0..4) |lane| hashers[lane].scalar.inner = inner[lane];
    }
    pub fn finalize4(hashers: *[4]@This()) [4]Hash {
        _ = finalizations.fetchAdd(1, .monotonic);
        var inner: [4]H = undefined;
        inline for (0..4) |lane| inner[lane] = hashers[lane].scalar.inner;
        return H.finalize4(&inner);
    }
};
const Columns = struct {
    a: std.mem.Allocator,
    values: [][]const M,
    fn deinit(self: *@This()) void {
        for (self.values) |v| self.a.free(v);
        self.a.free(self.values);
    }
    fn init(a: std.mem.Allocator, final_log: u5, mixed: bool) !@This() {
        const values = try a.alloc([]const M, 66);
        var made: usize = 0;
        errdefer {
            for (values[0..made]) |v| a.free(v);
            a.free(values);
        }
        for (values, 0..) |*column, i| {
            const log = if (mixed and i < 31) (if (final_log <= 12) final_log - 6 else 10) else if (mixed and i < 50) (if (final_log <= 12) final_log - 3 else 12) else final_log;
            const data = try a.alloc(M, @as(usize, 1) << log);
            column.* = data;
            made += 1;
            for (data, 0..) |*v, j| v.* = M.fromCanonical(@intCast((13 + i * 1009 + j * 701) % Core.fields.m31.Modulus));
        }
        return .{ .a = a, .values = values };
    }
};
fn commit(comptime Hasher: type, a: std.mem.Allocator, columns: []const []const M, budget: usize, comptime reuse: bool, stats: ?*E.vcs_lifted.prover.MerkleProverLifted(Hasher).BoundedPrefixStats) !E.vcs_lifted.prover.MerkleProverLifted(Hasher) {
    const Tree = E.vcs_lifted.prover.MerkleProverLifted(Hasher);
    const sorted = try Tree.sortColumnsByLogSizeAsc(a, columns);
    defer a.free(sorted);
    var builder = Tree.StreamingCommitter.init(a);
    errdefer builder.deinit();
    return if (reuse) try builder.commitColumnsWithReusedBoundedPrefix(sorted, budget, stats) else try builder.commitColumnsWithBoundedPrefix(sorted, budget, stats);
}
test "OP P2 bounded tails native packed dispatch and exact mixed equal tree parity" {
    const a = std.testing.allocator;
    for ([_]usize{ 1, 3 }) |worker_count| {
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = worker_count });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]bool{ false, true }) |mixed| {
            var columns = try Columns.init(a, 12, mixed);
            defer columns.deinit();
            var oracle = try commit(Scalar, a, columns.values, 2 * @sizeOf(Scalar), false, null);
            defer oracle.deinit(a);
            for ([_]usize{ 2, 1024, 4096 }) |states| inline for (.{ false, true }) |reuse| {
                Packed.updates.store(0, .monotonic);
                Packed.finalizations.store(0, .monotonic);
                var stats: E.vcs_lifted.prover.MerkleProverLifted(Packed).BoundedPrefixStats = .{};
                const budget = states * @sizeOf(Packed);
                var candidate = try commit(Packed, a, columns.values, budget, reuse, &stats);
                defer candidate.deinit(a);
                try std.testing.expectEqual(oracle.layers.len, candidate.layers.len);
                for (oracle.layers, candidate.layers) |x, y| try std.testing.expectEqualSlices(H.Hash, x, y);
                try std.testing.expect(stats.prefix_state_bytes <= budget);
                try std.testing.expect(Packed.updates.load(.monotonic) > 0);
                try std.testing.expect(Packed.finalizations.load(.monotonic) > 0);
            };
        }
    }
}
test "OP P2v2 exact native profile enables bounded prefix reuse" {
    const W = @import("pure_p2_worker_protocol.zig").W;
    var scheme = try W.Scheme.init(std.testing.allocator, @import("op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1.config());
    defer scheme.deinit(std.testing.allocator);
    try std.testing.expect(scheme.reuse_bounded_merkle_tail);
}
test "OP P2 bounded tail tiny benchmark identical geometry scalar vector reused" {
    if (!std.process.hasEnvVarConstant("STWO_OP_P2_BOUNDED_TAIL_BENCH")) return error.SkipZigTest;
    const a = std.heap.smp_allocator;
    var columns = try Columns.init(a, 16, true);
    defer columns.deinit();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var expected: ?H.Hash = null;
    inline for (.{ 0, 1, 2 }) |mode| {
        const Hasher = if (mode == 0) Scalar else H;
        const reuse = mode == 2;
        var timer = try std.time.Timer.start();
        var stats: E.vcs_lifted.prover.MerkleProverLifted(Hasher).BoundedPrefixStats = .{};
        var tree = try commit(Hasher, a, columns.values, 2 * @sizeOf(Hasher), reuse, &stats);
        const ns = timer.read();
        defer tree.deinit(a);
        if (expected) |root| try std.testing.expectEqualSlices(u8, &root, &tree.root()) else expected = tree.root();
        const json = try std.json.Stringify.valueAlloc(a, .{ .mode = mode, .elapsed_ns = ns, .stats = stats, .root = std.fmt.bytesToHex(tree.root(), .lower) }, .{});
        defer a.free(json);
        std.debug.print("OP_P2_BOUNDED_TAIL_BENCH {s}\n", .{json});
    }
}

test "OP P2 bounded tail preserves checked prefix and shared heap budgets" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 4 << 20);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var columns = try Columns.init(a, 12, true);
        defer columns.deinit();
        try std.testing.expectError(error.PrefixStateBudgetTooSmall, commit(H, a, columns.values, @sizeOf(H), true, null));
        var stats: E.vcs_lifted.prover.MerkleProverLifted(H).BoundedPrefixStats = .{};
        const prefix_budget = 1024 * @sizeOf(H);
        var candidate = try commit(H, a, columns.values, prefix_budget, true, &stats);
        defer candidate.deinit(a);
        try std.testing.expect(stats.prefix_state_bytes <= prefix_budget);
        try std.testing.expect(stats.leaf_phase_peak_bytes <= prefix_budget + stats.leaf_layer_bytes);
        try std.testing.expect(stats.tail_cache_bytes < 1 << 20);
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    try std.testing.expect(budget.snapshot().peak_live_bytes <= 4 << 20);
}

// Diagnostic only: count semantic work, not a timing oracle. Timed probes use
// the uninstrumented native hasher so atomics do not manufacture a speedup.
const WorkProbe = struct {
    inner: H,
    const Self = @This();
    var scalar_words: std.atomic.Value(usize) = .init(0);
    var packed_words: std.atomic.Value(usize) = .init(0);
    var scalar_permutations: std.atomic.Value(usize) = .init(0);
    var packed_permutations: std.atomic.Value(usize) = .init(0);
    var nodes: std.atomic.Value(usize) = .init(0);
    pub const Hash = H.Hash;
    pub const NodeSeed = void;
    pub fn nodeSeed() void {}
    pub fn defaultWithInitialState() Self {
        return .{ .inner = H.defaultWithInitialState() };
    }
    pub fn updateLeaf(self: *Self, values: []const M) void {
        _ = scalar_words.fetchAdd(values.len, .monotonic);
        _ = scalar_permutations.fetchAdd((self.inner.inner.at + values.len) / 12, .monotonic);
        self.inner.updateLeaf(values);
    }
    pub fn finalize(self: Self) Hash {
        _ = scalar_permutations.fetchAdd(1, .monotonic);
        return self.inner.finalize();
    }
    pub fn updateM31Columns4(hashers: *[4]Self, columns: anytype, position: usize) void {
        _ = packed_words.fetchAdd(4 * columns.len, .monotonic);
        _ = packed_permutations.fetchAdd(4 * ((hashers[0].inner.inner.at + columns.len) / 12), .monotonic);
        var inner: [4]H = undefined;
        inline for (0..4) |i| inner[i] = hashers[i].inner;
        H.updateM31Columns4(&inner, columns, position);
        inline for (0..4) |i| hashers[i].inner = inner[i];
    }
    pub fn finalize4(hashers: *[4]Self) [4]Hash {
        _ = packed_permutations.fetchAdd(4, .monotonic);
        var inner: [4]H = undefined;
        inline for (0..4) |i| inner[i] = hashers[i].inner;
        return H.finalize4(&inner);
    }
    pub fn hashChildren(children: struct { left: Hash, right: Hash }) Hash {
        _ = nodes.fetchAdd(1, .monotonic);
        return H.hashChildren(.{ .left = children.left, .right = children.right });
    }
    pub fn hashChildrenWithSeed(_: void, children: struct { left: Hash, right: Hash }) Hash {
        return hashChildren(.{ .left = children.left, .right = children.right });
    }
    pub fn hashChildrenWithSeed4(_: void, children: *const [8]Hash) [4]Hash {
        _ = nodes.fetchAdd(4, .monotonic);
        return H.hashChildrenWithSeed4({}, children);
    }
};
test "OP P2 reused intermediate semantic work diagnostic" {
    if (!std.process.hasEnvVarConstant("STWO_OP_P2_INTERMEDIATE_WORK")) return error.SkipZigTest;
    const a = std.testing.allocator;
    var columns = try Columns.init(a, 16, true);
    defer columns.deinit();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    WorkProbe.scalar_words.store(0, .monotonic);
    WorkProbe.packed_words.store(0, .monotonic);
    WorkProbe.scalar_permutations.store(0, .monotonic);
    WorkProbe.packed_permutations.store(0, .monotonic);
    WorkProbe.nodes.store(0, .monotonic);
    var stats: E.vcs_lifted.prover.MerkleProverLifted(WorkProbe).BoundedPrefixStats = .{};
    var tree = try commit(WorkProbe, a, columns.values, 2 * @sizeOf(WorkProbe), true, &stats);
    defer tree.deinit(a);
    const info = try std.json.Stringify.valueAlloc(a, .{ .scalar_absorbed_words = WorkProbe.scalar_words.load(.monotonic), .native4_absorbed_words = WorkProbe.packed_words.load(.monotonic), .scalar_leaf_state_permutations = WorkProbe.scalar_permutations.load(.monotonic), .native4_leaf_state_permutations = WorkProbe.packed_permutations.load(.monotonic), .binary_nodes = WorkProbe.nodes.load(.monotonic), .internal_state_permutations = 2 * WorkProbe.nodes.load(.monotonic), .stats = stats, .root = std.fmt.bytesToHex(tree.root(), .lower), .timing_claim = false }, .{});
    defer a.free(info);
    std.debug.print("OP_P2_INTERMEDIATE_WORK {s}\n", .{info});
}
