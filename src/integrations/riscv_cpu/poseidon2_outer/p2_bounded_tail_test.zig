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
// Retains native-four final updates/nodes while disabling only the new
// intermediate tile cache, for a like-for-like uninstrumented control.
const LegacyNative = struct {
    inner: H,
    pub const native_four_intermediate_tiles = false;
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
    pub fn hashChildrenWithSeed4(_: void, children: *const [8]Hash) [4]Hash {
        return H.hashChildrenWithSeed4({}, children);
    }
    pub fn updateM31Columns4(hashers: *[4]@This(), columns: anytype, position: usize) void {
        var inner: [4]H = undefined;
        inline for (0..4) |i| inner[i] = hashers[i].inner;
        H.updateM31Columns4(&inner, columns, position);
        inline for (0..4) |i| hashers[i].inner = inner[i];
    }
    pub fn finalize4(hashers: *[4]@This()) [4]Hash {
        var inner: [4]H = undefined;
        inline for (0..4) |i| inner[i] = hashers[i].inner;
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
    inline for (.{ 0, 1, 2, 3 }) |mode| {
        const Hasher = if (mode == 0) Scalar else if (mode == 2) LegacyNative else H;
        const reuse = mode >= 2;
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

fn oomTiles(a: std.mem.Allocator) !void {
    const c2 = [_]M{M.fromCanonical(3)} ** 2;
    const c4 = [_]M{M.fromCanonical(5)} ** 4;
    const c16 = [_]M{M.fromCanonical(7)} ** 16;
    var tree = try commit(H, a, &.{ &c2, &c4, &c16 }, 2 * @sizeOf(H), true, null);
    defer tree.deinit(a);
}
test "OP P2 native four cache minimum log and full-prefix empty and OOM gates" {
    const a = std.testing.allocator;
    const c1 = [_]M{M.fromCanonical(2)};
    const c2 = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    const c4 = [_]M{ M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17) };
    try std.testing.expectError(error.InvalidColumnSize, commit(H, a, &.{&c1}, 2 * @sizeOf(H), true, null));
    try std.testing.expectError(error.InvalidColumnSize, E.vcs_lifted.prover.MerkleProverLifted(H).commit(a, &.{&c1}));
    for ([_][]const []const M{ &.{}, &.{&c2}, &.{ &c2, &c4 } }) |columns| {
        var oracle = try commit(Scalar, a, columns, 4 * @sizeOf(Scalar), true, null);
        defer oracle.deinit(a);
        var actual = try commit(H, a, columns, 4 * @sizeOf(H), true, null);
        defer actual.deinit(a);
        for (oracle.layers, actual.layers) |x, y| try std.testing.expectEqualSlices(H.Hash, x, y);
    }
    try std.testing.checkAllAllocationFailures(a, oomTiles, .{});
}
test "OP P2 native four intermediate cache leaf parity on unaligned short ranges and missing final suffix" {
    const Tree = E.vcs_lifted.prover.MerkleProverLifted(H);
    const Tiles = E.vcs_lifted.native_four_tail.For(H, Tree.ColumnRef);
    var c2: [2]M = undefined;
    var c4: [4]M = undefined;
    var c16: [16]M = undefined;
    for (&c2, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 3));
    for (&c4, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 7));
    for (&c16, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 13));
    const cols = [_]Tree.ColumnRef{ .{ .log_size = 1, .values = &c2, .original_index = 0 }, .{ .log_size = 2, .values = &c4, .original_index = 1 }, .{ .log_size = 4, .values = &c16, .original_index = 2 } };
    var base = [_]H{ H.defaultWithInitialState(), H.defaultWithInitialState() };
    // Nonzero and equal absorption counters across independently seeded parity
    // states. Neither source prefix state may be mutated by a tail worker.
    const seed = [_]M{M.fromCanonical(23)} ** 13;
    for (&base) |*state| state.updateLeaf(&seed);
    const saved = base;
    for ([_]usize{ 0, 1, 3 }) |column_count| for ([_][2]usize{ .{ 0, 0 }, .{ 0, 64 }, .{ 1, 5 }, .{ 1, 33 }, .{ 3, 63 }, .{ 7, 12 }, .{ 63, 64 } }) |span| {
        var actual: [64]H.Hash = @splat(@splat(0xff));
        const Range = struct { base_hashers: []const H, base_log_size: u32, tail_columns: []const Tree.ColumnRef, final_log_size: u32, leaves: []H.Hash, start: usize, end: usize };
        const range = Range{ .base_hashers = &base, .base_log_size = 1, .tail_columns = cols[0..column_count], .final_log_size = 6, .leaves = &actual, .start = span[0], .end = span[1] };
        _ = Tiles.finish(&range);
        for (actual, 0..) |value, row| {
            if (row < span[0] or row >= span[1]) {
                try std.testing.expectEqualSlices(u8, &(@as(H.Hash, @splat(0xff))), &value);
                continue;
            }
            var oracle = base[row & 1];
            for (cols[0..column_count]) |column| {
                const shift: std.math.Log2Int(usize) = @intCast(6 - column.log_size + 1);
                const index = ((row >> shift) << 1) + (row & 1);
                oracle.updateLeaf(column.values[index..][0..1]);
            }
            try std.testing.expectEqualSlices(u8, &oracle.finalize(), &value);
        }
        inline for (0..2) |i| try std.testing.expectEqualDeep(saved[i], base[i]);
    };
}

test "OP P2 native intermediate cache more than64 sameheight columns and nested heights" {
    const Tree = E.vcs_lifted.prover.MerkleProverLifted(H);
    const Tiles = E.vcs_lifted.native_four_tail.For(H, Tree.ColumnRef);
    const c2 = [_]M{ M.fromCanonical(3), M.fromCanonical(7) };
    const c4 = [_]M{ M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17), M.fromCanonical(19) };
    const base = [_]H{ H.defaultWithInitialState(), H.defaultWithInitialState() };
    for ([_]bool{ false, true }) |two_rows| {
        var columns: [70]Tree.ColumnRef = undefined;
        for (&columns, 0..) |*column, i| column.* = .{ .log_size = if (two_rows) 1 else 2, .values = if (two_rows) &c2 else &c4, .original_index = i };
        var actual: [64]H.Hash = undefined;
        const Range = struct { base_hashers: []const H, base_log_size: u32, tail_columns: []const Tree.ColumnRef, final_log_size: u32, leaves: []H.Hash, start: usize, end: usize };
        const range = Range{ .base_hashers = &base, .base_log_size = 1, .tail_columns = &columns, .final_log_size = 6, .leaves = &actual, .start = 0, .end = 64 };
        _ = Tiles.finish(&range);
        for (actual, 0..) |value, row| {
            var oracle = base[row & 1];
            for (columns) |column| {
                const shift: std.math.Log2Int(usize) = @intCast(6 - column.log_size + 1);
                const index = ((row >> shift) << 1) + (row & 1);
                oracle.updateLeaf(column.values[index..][0..1]);
            }
            try std.testing.expectEqualSlices(u8, &oracle.finalize(), &value);
        }
    }
    var storage: [8][256]M = undefined;
    var columns: [8][]const M = undefined;
    for (&storage, &columns, 0..) |*values, *column, log_minus1| {
        const n = @as(usize, 1) << @intCast(log_minus1 + 1);
        for (values[0..n], 0..) |*v, i| v.* = M.fromCanonical(@intCast(29 + 31 * log_minus1 + i));
        column.* = values[0..n];
    }
    var oracle = try commit(Scalar, std.testing.allocator, &columns, 2 * @sizeOf(Scalar), false, null);
    defer oracle.deinit(std.testing.allocator);
    var actual = try commit(H, std.testing.allocator, &columns, 2 * @sizeOf(H), true, null);
    defer actual.deinit(std.testing.allocator);
    for (oracle.layers, actual.layers) |x, y| try std.testing.expectEqualSlices(H.Hash, x, y);
}
fn timedReuse(comptime Hasher: type, a: std.mem.Allocator, columns: []const []const M) !u64 {
    var timer = try std.time.Timer.start();
    var tree = try commit(Hasher, a, columns, 2 * @sizeOf(Hasher), true, null);
    const ns = timer.read();
    defer tree.deinit(a);
    try std.testing.expectEqualStrings("36979c0f4855646f3f2ce14e44b2891544b8e76c17d2550d29dc270d2db3ab2861d6e16a", &std.fmt.bytesToHex(tree.root(), .lower));
    return ns;
}
test "OP P2 native intermediate balanced uninstrumented microqualification" {
    if (!std.process.hasEnvVarConstant("STWO_OP_P2_INTERMEDIATE_BALANCED")) return error.SkipZigTest;
    const a = std.heap.smp_allocator;
    var columns = try Columns.init(a, 16, true);
    defer columns.deinit();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var control: [8]u64 = undefined;
    var candidate: [8]u64 = undefined;
    for (0..8) |round| {
        if (round % 2 == 0) {
            control[round] = try timedReuse(LegacyNative, a, columns.values);
            candidate[round] = try timedReuse(H, a, columns.values);
        } else {
            candidate[round] = try timedReuse(H, a, columns.values);
            control[round] = try timedReuse(LegacyNative, a, columns.values);
        }
    }
    const data = try std.json.Stringify.valueAlloc(a, .{ .control_ns = control, .candidate_ns = candidate, .pattern = "AB BA AB BA AB BA AB BA", .workers = 1, .whole_proof_claim = false }, .{});
    defer a.free(data);
    std.debug.print("OP_P2_NATIVE_TILES_BALANCED {s}\n", .{data});
}
