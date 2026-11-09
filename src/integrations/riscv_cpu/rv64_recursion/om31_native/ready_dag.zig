//! Exact serial node identities with completion-order-independent ready dispatch.
//! A successful completion means verified AND durably published. A parent keeps
//! both children live until then. Output slots include active wide graphs.
const std = @import("std");
pub const max_leaves = 256;
pub const max_nodes = 2 * max_leaves - 1;
/// Largest fold arity (m3). r1 is binary and keeps its exact node identities.
pub const max_arity = 4;
pub const Node = struct {
    first_leaf: usize,
    leaf_count: usize,
    /// Ordered, adjacent children; 0 for a leaf, otherwise 2..max_arity.
    arity: u8 = 0,
    children: [max_arity]usize = @splat(0),
    pub fn isLeaf(self: Node) bool {
        return self.arity == 0;
    }
    pub fn kids(self: *const Node) []const usize {
        return self.children[0..self.arity];
    }
    /// Binary view kept for r1 consumers (tree.json schema 2).
    pub fn left(self: Node) ?usize {
        return if (self.arity == 0) null else self.children[0];
    }
    pub fn right(self: Node) ?usize {
        return if (self.arity == 0) null else self.children[self.arity - 1];
    }
};
/// Fold arity policy: the caller supplies the outer profile's default (r1: 2,
/// m3: 4). `STWO_RV64_FOLD_ARITY` (2..4) overrides it identically for producer
/// and receiver; it changes node identities, digests and the root only.
pub fn policyArity(profile_default: usize) !usize {
    var buffer: [16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const value = if (std.process.getEnvVarOwned(fba.allocator(), "STWO_RV64_FOLD_ARITY")) |text|
        std.fmt.parseInt(usize, text, 10) catch return error.InvalidRecursiveFoldArity
    else |err| switch (err) {
        error.EnvironmentVariableNotFound => profile_default,
        // A set but unreadable value (e.g. too long) fails closed.
        else => return error.InvalidRecursiveFoldArity,
    };
    if (value < 2 or value > max_arity) return error.InvalidRecursiveFoldArity;
    return value;
}
pub const Plan = struct {
    nodes: [max_nodes]Node = undefined,
    /// Edges between the node and the root (root = 0). Scheduling only.
    depth: [max_nodes]u8 = @splat(0),
    count: usize = 0,
    root: usize = 0,
    arity: usize = 2,
    pub fn init(leaves: usize) !Plan {
        return initArity(leaves, 2);
    }
    /// Streaming k-ary carry. Leaves arrive in order; a level that holds k
    /// ready nodes folds them immediately. Finalization folds each level's
    /// remainder together with the carry from below (rightmost/smallest block
    /// upward). For k = 2 this is exactly the historical binary carry, so
    /// every r1 node identity is unchanged.
    pub fn initArity(leaves: usize, arity: usize) !Plan {
        if (leaves == 0 or leaves > max_leaves) return error.InvalidRecursionLeaves;
        if (arity < 2 or arity > max_arity) return error.InvalidRecursiveFoldArity;
        var self: Plan = .{ .arity = arity };
        var stack: [9][max_arity]usize = undefined;
        var depth = [_]usize{0} ** 9;
        for (0..leaves) |ordinal| {
            var current = self.append(.{ .first_leaf = ordinal, .leaf_count = 1 });
            var level: usize = 0;
            while (depth[level] + 1 == arity) : (level += 1) {
                var group: [max_arity]usize = undefined;
                @memcpy(group[0 .. arity - 1], stack[level][0 .. arity - 1]);
                group[arity - 1] = current;
                current = self.parent(group[0..arity]);
                depth[level] = 0;
            }
            stack[level][depth[level]] = current;
            depth[level] += 1;
        }
        var carry: ?usize = null;
        for (&stack, depth) |*entries, n| {
            var group: [max_arity]usize = undefined;
            @memcpy(group[0..n], entries[0..n]);
            var m = n;
            if (carry) |c| {
                group[m] = c;
                m += 1;
            }
            if (m == 1) carry = group[0] else if (m >= 2) carry = self.parent(group[0..m]);
        }
        self.root = carry.?;
        std.debug.assert(self.nodes[self.root].leaf_count == leaves);
        // Children precede parents, so a reverse sweep sees every parent first.
        var id = self.count;
        while (id > 0) {
            id -= 1;
            for (self.nodes[id].kids()) |kid| self.depth[kid] = self.depth[id] + 1;
        }
        return self;
    }
    /// sched M6 device priority (higher first): deeper nodes carry the longer
    /// remaining fold chain; at equal depth a leaf precedes a fold.
    pub fn priority(self: *const Plan, id: usize) u32 {
        return @as(u32, self.depth[id]) * 2 + @intFromBool(self.nodes[id].isLeaf());
    }
    fn append(self: *Plan, node: Node) usize {
        const id = self.count;
        self.nodes[id] = node;
        self.count += 1;
        return id;
    }
    fn parent(self: *Plan, group: []const usize) usize {
        std.debug.assert(group.len >= 2 and group.len <= max_arity);
        var node = Node{ .first_leaf = self.nodes[group[0]].first_leaf, .leaf_count = 0, .arity = @intCast(group.len) };
        for (group, 0..) |id, i| {
            const child = self.nodes[id];
            std.debug.assert(node.first_leaf + node.leaf_count == child.first_leaf);
            node.leaf_count += child.leaf_count;
            node.children[i] = id;
        }
        return self.append(node);
    }
    /// Retained done-but-unconsumed children are bounded by (arity-1) per
    /// carry level; this is the admission floor for `Queue`.
    pub fn minimumLimit(self: *const Plan, lanes: usize) usize {
        return @max(9 + 2 * lanes, self.carryBound() + 2 * lanes + 1);
    }
    /// Retained carry entries of an in-order leaf sequence: (arity-1) per level.
    pub fn carryBound(self: *const Plan) usize {
        var levels: usize = 0;
        var width: usize = 1;
        while (width < max_leaves) : (levels += 1) width *= self.arity;
        return (self.arity - 1) * levels;
    }
};
pub const LaneIdentity = struct { device: u32, factory: usize, pool: usize, workers: usize };
pub fn validateLanes(lanes: []const LaneIdentity, pool_worker_budget: usize, limit: usize) !void {
    if (lanes.len == 0 or lanes.len > 4 or limit < 9 + 2 * lanes.len) return error.InvalidRecursionAdmission;
    var workers: usize = 0;
    for (lanes, 0..) |lane, i| {
        if (lane.workers == 0) return error.InvalidRecursionPoolBudget;
        workers = try std.math.add(usize, workers, lane.workers);
        for (lanes[0..i]) |other| {
            if (lane.device == other.device or lane.factory == other.factory or lane.pool == other.pool) return error.DuplicateRecursionDeviceLane;
        }
    }
    if (workers > pool_worker_budget) return error.InvalidRecursionPoolBudget;
}
pub const Status = enum { pending, running, done, retired, failed };
/// Operational scramble test: only ready device work is reordered. The carry
/// plan, ordered children, transcript and bounded host admission stay intact.
pub fn scrambleSeedFromEnv() !?u64 {
    return null;
}
pub fn scrambleRank(seed: u64, dispatch: u64, node: usize) u64 {
    var x = seed ^ (dispatch *% 0x9e3779b97f4a7c15) ^ @as(u64, @intCast(node));
    x +%= 0x9e3779b97f4a7c15;
    x = (x ^ (x >> 30)) *% 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) *% 0x94d049bb133111eb;
    return x ^ (x >> 31);
}
test "seeded device order is repeatable and changes without changing the DAG" {
    var changed = false;
    for (0..19) |i| {
        try std.testing.expectEqual(scrambleRank(17, 0, i), scrambleRank(17, 0, i));
        changed = changed or scrambleRank(17, 0, i) != scrambleRank(29, 0, i);
    }
    try std.testing.expect(changed);
}
/// Dispatch order only; plan, node identities and proof bytes never depend on it.
/// `m5` (default): lowest pending leaf id, device lanes widest parent first.
/// `critical` (opt-in): pending leaves and device starts by depth below the
/// root (deeper first, then id).
pub const Policy = enum {
    m5,
    critical,
    pub fn fromEnv() !Policy {
        // Default m5: the critical device order measured slower on 24628607
        // (deferred folds hold authority slots and starve leaf admission).
        return .m5;
    }
};
pub const LeafSet = std.StaticBitSet(max_leaves);
pub const Queue = struct {
    plan: *const Plan,
    status: [max_nodes]Status = @splat(.pending),
    limit: usize,
    live: usize = 0,
    active: usize = 0,
    completed: usize = 0,
    peak: usize = 0,
    failure: ?struct { node: usize, err: anyerror } = null,
    policy: Policy = .m5,
    lanes: usize = 1,
    /// Leaves (by first_leaf ordinal) whose inputs are not yet available
    /// (streaming native handoff). A closed leaf is never taken.
    closed: LeafSet = LeafSet.initEmpty(),
    pub fn init(plan: *const Plan, lanes: usize, limit: usize) !Queue {
        if (lanes == 0 or lanes > 4 or limit < plan.minimumLimit(lanes)) return error.InvalidRecursionAdmission;
        return .{ .plan = plan, .limit = limit, .lanes = lanes };
    }
    pub fn initPolicy(plan: *const Plan, lanes: usize, limit: usize, policy: Policy) !Queue {
        var q = try init(plan, lanes, limit);
        q.policy = policy;
        return q;
    }
    pub fn closeAllLeaves(self: *Queue) void {
        self.closed = LeafSet.initEmpty();
        self.closed.setRangeValue(.{ .start = 0, .end = self.plan.nodes[self.plan.root].leaf_count }, true);
    }
    pub fn openLeaf(self: *Queue, ordinal: usize) void {
        self.closed.unset(ordinal);
    }
    fn leafChoice(self: *const Queue) ?usize {
        var best: ?usize = null;
        // Near the admission limit keep the M5 carry order (lowest pending
        // leaf), whose retained-children bound is what minimumLimit proves.
        // Out-of-order leaves may only use the slots above the carry reserve:
        // scattered (< limit - reserve) + carry + active stays below limit.
        const reserve = self.plan.carryBound() + self.lanes + 2;
        const sequential = self.policy == .m5 or self.live + self.active + reserve >= self.limit;
        for (self.plan.nodes[0..self.plan.count], 0..) |node, i| {
            if (self.status[i] != .pending or !node.isLeaf()) continue;
            if (sequential) {
                // The carry order is by ordinal; a closed lowest leaf blocks.
                if (self.closed.isSet(node.first_leaf)) return null;
                return i;
            }
            if (self.closed.isSet(node.first_leaf)) continue;
            if (best == null or self.plan.depth[i] > self.plan.depth[best.?]) best = i;
        }
        return best;
    }
    pub fn take(self: *Queue) !?usize {
        return self.takeFiltered(true);
    }
    /// Same admission as take(); with `leaves` false only a ready parent may
    /// start (a host prep pool bounds how many leaves it prepares ahead).
    pub fn takeFiltered(self: *Queue, leaves: bool) !?usize {
        if (self.failure != null or self.completed == self.plan.count) return null;
        // A newly generated parent needs an additional slot until its two
        // children can be retired. Leaves always leave that slot available.
        if (self.live + self.active < self.limit) {
            for (self.plan.nodes[0..self.plan.count], 0..) |*node, i| {
                if (self.status[i] != .pending or node.isLeaf()) continue;
                const ready = for (node.kids()) |kid| {
                    if (self.status[kid] != .done) break false;
                } else true;
                if (ready) return self.start(i);
            }
        }
        if (leaves and self.live + self.active + 1 < self.limit) {
            if (self.leafChoice()) |i| return self.start(i);
        }
        // A leaf still waiting for its native proof is progress, not deadlock.
        if (self.active == 0 and leaves and self.closed.count() == 0) return error.RecursiveReadyDeadlock;
        return null;
    }
    fn start(self: *Queue, id: usize) usize {
        self.status[id] = .running;
        self.active += 1;
        self.peak = @max(self.peak, self.live + self.active);
        return id;
    }
    pub fn complete(self: *Queue, id: usize) void {
        std.debug.assert(self.status[id] == .running);
        self.active -= 1;
        self.live += 1;
        self.completed += 1;
        self.status[id] = .done;
        const node = &self.plan.nodes[id];
        for (node.kids()) |kid| {
            std.debug.assert(self.status[kid] == .done);
            self.status[kid] = .retired;
            self.live -= 1;
        }
    }
    pub fn fail(self: *Queue, id: usize, err: anyerror) void {
        std.debug.assert(self.status[id] == .running);
        self.active -= 1;
        self.status[id] = .failed;
        if (self.failure == null or id < self.failure.?.node) self.failure = .{ .node = id, .err = err };
    }
};

/// Production and host mocks share this exact blocking dispatcher. Publication
/// runs under the same mutex before children become ready to their consumer.
pub const Dispatcher = struct {
    queue: Queue,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    fatal: ?anyerror = null,
    pub fn take(self: *Dispatcher) !?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.fatal != null or self.queue.failure != null or self.queue.completed == self.queue.plan.count) return null;
            const next = self.queue.take() catch |err| {
                self.fatal = err;
                self.changed.broadcast();
                return err;
            };
            if (next != null) return next;
            self.changed.wait(&self.mutex);
        }
    }
    pub fn publish(self: *Dispatcher, id: usize, context: *anyopaque, apply: *const fn (*anyopaque, usize) void) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        apply(context, id);
        self.queue.complete(id);
        self.changed.broadcast();
    }
    pub fn fail(self: *Dispatcher, id: usize, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.queue.fail(id, err);
        self.changed.broadcast();
    }
    pub fn stop(self: *Dispatcher, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
        self.changed.broadcast();
    }
    /// Read only after all lane threads have joined.
    pub fn result(self: *const Dispatcher) !void {
        if (self.fatal) |err| return err;
        if (self.queue.failure) |failure| return failure.err;
        if (self.queue.completed != self.queue.plan.count or self.queue.active != 0 or self.queue.live != 1) return error.RecursiveLeafCoverage;
    }
};

test "ready recursion preserves exact binary carry IDs and right finalization" {
    const plan = try Plan.init(5);
    const B = struct {
        fn n(first: usize, count: usize, l: usize, r: usize) Node {
            return .{ .first_leaf = first, .leaf_count = count, .arity = 2, .children = .{ l, r, 0, 0 } };
        }
    };
    const expected = [_]Node{
        .{ .first_leaf = 0, .leaf_count = 1 }, .{ .first_leaf = 1, .leaf_count = 1 },
        B.n(0, 2, 0, 1),                       .{ .first_leaf = 2, .leaf_count = 1 },
        .{ .first_leaf = 3, .leaf_count = 1 }, B.n(2, 2, 3, 4),
        B.n(0, 4, 2, 5),                       .{ .first_leaf = 4, .leaf_count = 1 },
        B.n(0, 5, 6, 7),
    };
    try std.testing.expectEqualDeep(&expected, plan.nodes[0..plan.count]);
    try std.testing.expectEqual(@as(usize, 2 * 5 - 1), plan.count);
    for (1..257) |n| {
        const p = try Plan.init(n);
        try std.testing.expectEqual(n, p.nodes[p.root].leaf_count);
        try std.testing.expectEqual(2 * n - 1, p.count);
        for (p.nodes[0..p.count], 0..) |node, id| if (node.isLeaf()) {
            try std.testing.expectEqual(2 * node.first_leaf - @popCount(node.first_leaf), id);
        };
    }
}

test "ready recursion bounds retained children and active graphs under adversarial completion" {
    for (1..5) |lanes| for (1..257) |n| {
        const plan = try Plan.init(n);
        var q = try Queue.init(&plan, lanes, 9 + 2 * lanes);
        var active: std.ArrayList(usize) = .empty;
        defer active.deinit(std.testing.allocator);
        while (q.completed < plan.count) {
            while (active.items.len < lanes) {
                const next = try q.take() orelse break;
                try active.append(std.testing.allocator, next);
            }
            try std.testing.expect(active.items.len != 0);
            // Complete newest first; leaves/parents can finish out of ID order.
            const id = active.pop().?;
            q.complete(id);
            try std.testing.expect(q.live + q.active <= q.limit);
        }
        try std.testing.expectEqual(@as(usize, 1), q.live);
        try std.testing.expectEqual(Status.done, q.status[plan.root]);
    };
}

test "ready recursion stops dispatch after failure and drains deterministic failure order" {
    const plan = try Plan.init(4);
    var q = try Queue.init(&plan, 2, 13);
    const first = (try q.take()).?;
    const second = (try q.take()).?;
    q.fail(second, error.Second);
    try std.testing.expectEqual(@as(?usize, null), try q.take());
    q.fail(first, error.First);
    try std.testing.expectEqual(error.First, q.failure.?.err);
    try std.testing.expectEqual(@as(usize, 0), q.active);
    try std.testing.expectError(error.InvalidRecursionAdmission, Queue.init(&plan, 4, 5));
}

test "ready recursion rejects aliased physical factories pools and CPU oversubscription" {
    var lanes = [_]LaneIdentity{ .{ .device = 0, .factory = 1, .pool = 2, .workers = 4 }, .{ .device = 1, .factory = 3, .pool = 4, .workers = 4 } };
    try validateLanes(&lanes, 8, 13);
    try std.testing.expectError(error.InvalidRecursionPoolBudget, validateLanes(&lanes, 7, 13));
    lanes[1].device = 0;
    try std.testing.expectError(error.DuplicateRecursionDeviceLane, validateLanes(&lanes, 8, 13));
    lanes[1].device = 1;
    lanes[1].factory = 1;
    try std.testing.expectError(error.DuplicateRecursionDeviceLane, validateLanes(&lanes, 8, 13));
    lanes[1].factory = 3;
    lanes[1].pool = 2;
    try std.testing.expectError(error.DuplicateRecursionDeviceLane, validateLanes(&lanes, 8, 13));
}

const ThreadMock = struct {
    dispatch: Dispatcher,
    durable: [max_nodes]bool = @splat(false),
    retained: [max_nodes]bool = @splat(false),
    graphs_live: std.atomic.Value(usize) = .init(0),
    started: std.atomic.Value(usize) = .init(0),
    second_failed: std.atomic.Value(bool) = .init(false),
    fail_pair: bool = false,
    fn runLane(self: *ThreadMock) void {
        while (self.dispatch.take() catch unreachable) |id| {
            _ = self.graphs_live.fetchAdd(1, .seq_cst);
            _ = self.started.fetchAdd(1, .seq_cst);
            if (self.fail_pair) {
                while (self.started.load(.seq_cst) != 2) std.Thread.yield() catch {};
                if (id == 0) {
                    while (!self.second_failed.load(.seq_cst)) std.Thread.yield() catch {};
                }
                _ = self.graphs_live.fetchSub(1, .seq_cst);
                self.dispatch.fail(id, if (id == 0) error.First else error.Second);
                if (id != 0) self.second_failed.store(true, .seq_cst);
                return;
            }
            // Yield before durable publication, while child ownership remains
            // reserved by the real production dispatcher.
            for (0..1 + id % 7) |_| std.Thread.yield() catch {};
            _ = self.graphs_live.fetchSub(1, .seq_cst);
            self.dispatch.publish(id, self, publish);
        }
    }
    fn publish(raw: *anyopaque, id: usize) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const node = &self.dispatch.queue.plan.nodes[id];
        for (node.kids()) |kid| {
            std.debug.assert(self.durable[kid] and self.retained[kid]);
            self.retained[kid] = false;
        }
        std.debug.assert(!self.durable[id] and !self.retained[id]);
        self.durable[id] = true;
        self.retained[id] = true;
    }
};

test "ready production dispatcher threads publish before parent release and fully join" {
    for (1..5) |lanes| {
        const plan = try Plan.init(33);
        var mock = ThreadMock{ .dispatch = .{ .queue = try Queue.init(&plan, lanes, 9 + 2 * lanes) } };
        var threads: [4]std.Thread = undefined;
        var launched: usize = 0;
        errdefer {
            mock.dispatch.stop(error.SpawnFailed);
            for (threads[0..launched]) |thread| thread.join();
        }
        for (0..lanes) |lane| {
            threads[lane] = try std.Thread.spawn(.{}, ThreadMock.runLane, .{&mock});
            launched += 1;
        }
        for (threads[0..launched]) |thread| thread.join();
        launched = 0;
        try mock.dispatch.result();
        try std.testing.expectEqual(@as(usize, 0), mock.graphs_live.load(.seq_cst));
        var retained: usize = 0;
        for (0..plan.count) |id| {
            try std.testing.expect(mock.durable[id]);
            retained += @intFromBool(mock.retained[id]);
        }
        try std.testing.expectEqual(@as(usize, 1), retained);
        try std.testing.expect(mock.retained[plan.root]);
    }
}

test "ready production dispatcher threads cancel dispatch drain failures and preserve publication ownership" {
    const plan = try Plan.init(17);
    var mock = ThreadMock{ .dispatch = .{ .queue = try Queue.init(&plan, 2, 13) }, .fail_pair = true };
    const first = try std.Thread.spawn(.{}, ThreadMock.runLane, .{&mock});
    const second = std.Thread.spawn(.{}, ThreadMock.runLane, .{&mock}) catch |err| {
        // Release the test's two-lane barrier if the OS rejects a thread.
        mock.started.store(2, .seq_cst);
        mock.second_failed.store(true, .seq_cst);
        mock.dispatch.stop(err);
        first.join();
        return err;
    };
    first.join();
    second.join();
    try std.testing.expectError(error.First, mock.dispatch.result());
    try std.testing.expectEqual(@as(usize, 2), mock.started.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), mock.graphs_live.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), mock.dispatch.queue.active);
    try std.testing.expectEqual(@as(?usize, null), try mock.dispatch.take());
    for (0..plan.count) |id| {
        try std.testing.expect(!mock.durable[id]);
        try std.testing.expect(!mock.retained[id]);
    }
}

test "ready recursion parent-only admission never starts a leaf and never reports a false deadlock" {
    const plan = try Plan.init(5);
    var q = try Queue.init(&plan, 2, 13);
    try std.testing.expectEqual(@as(?usize, null), try q.takeFiltered(false));
    const first = (try q.take()).?;
    const second = (try q.take()).?;
    try std.testing.expectEqual(@as(?usize, null), try q.takeFiltered(false));
    q.complete(first);
    q.complete(second);
    // Leaves 0 and 1 are done: their parent is the only parent-only candidate.
    try std.testing.expectEqual(@as(?usize, 2), try q.takeFiltered(false));
    try std.testing.expectEqual(@as(?usize, null), try q.takeFiltered(false));
    try std.testing.expect((try q.takeFiltered(true)) != null);
}

test "ready recursion admission stays live with pipelined prep-ahead concurrency above lane count" {
    // The pipelined executor keeps up to prep_ahead + lanes + finishing nodes
    // active at once under the unchanged 17-slot authority limit.
    for ([_]usize{ 4, 6, 8, 12, 16 }) |concurrency| for (1..257) |n| {
        const plan = try Plan.init(n);
        var q = try Queue.init(&plan, 2, 17);
        var active: std.ArrayList(usize) = .empty;
        defer active.deinit(std.testing.allocator);
        var step: usize = 0;
        while (q.completed < plan.count) : (step += 1) {
            while (active.items.len < concurrency) {
                const next = try q.take() orelse break;
                try active.append(std.testing.allocator, next);
            }
            try std.testing.expect(active.items.len != 0);
            // Alternate newest-first and oldest-first completion.
            const id = if (step % 2 == 0) active.pop().? else active.orderedRemove(0);
            q.complete(id);
            try std.testing.expect(q.live + q.active <= q.limit);
        }
        try std.testing.expectEqual(@as(usize, 1), q.live);
    };
}

test "m3 4-ary plan: 17 leaves fold in 6 nodes of depth 3, ordered, covering, bounded" {
    const plan = try Plan.initArity(17, 4);
    try std.testing.expectEqual(@as(usize, 17 + 6), plan.count);
    var depth: [max_nodes]usize = @splat(0);
    var max_depth: usize = 0;
    for (plan.nodes[0..plan.count], 0..) |*node, id| {
        if (node.isLeaf()) continue;
        try std.testing.expect(node.arity >= 2 and node.arity <= 4);
        var next = node.first_leaf;
        for (node.kids()) |kid| {
            try std.testing.expect(kid < id);
            try std.testing.expectEqual(next, plan.nodes[kid].first_leaf);
            next += plan.nodes[kid].leaf_count;
            depth[id] = @max(depth[id], depth[kid] + 1);
        }
        try std.testing.expectEqual(node.first_leaf + node.leaf_count, next);
        max_depth = @max(max_depth, depth[id]);
    }
    try std.testing.expectEqual(@as(usize, 3), max_depth);
    try std.testing.expectEqual(@as(usize, 17), plan.nodes[plan.root].leaf_count);
    for (2..5) |arity| for (1..257) |n| {
        const p = try Plan.initArity(n, arity);
        try std.testing.expectEqual(n, p.nodes[p.root].leaf_count);
        try std.testing.expectEqual(p.count - 1, p.root);
        var leaves: usize = 0;
        for (p.nodes[0..p.count]) |node| leaves += @intFromBool(node.isLeaf());
        try std.testing.expectEqual(n, leaves);
        for (1..5) |lanes| {
            var q = try Queue.init(&p, lanes, p.minimumLimit(lanes));
            var active: std.ArrayList(usize) = .empty;
            defer active.deinit(std.testing.allocator);
            while (q.completed < p.count) {
                while (active.items.len < lanes) {
                    const next = try q.take() orelse break;
                    try active.append(std.testing.allocator, next);
                }
                try std.testing.expect(active.items.len != 0);
                const id = active.pop().?;
                q.complete(id);
                try std.testing.expect(q.live + q.active <= q.limit);
            }
            try std.testing.expectEqual(@as(usize, 1), q.live);
        }
    };
    try std.testing.expectError(error.InvalidRecursiveFoldArity, Plan.initArity(5, 5));
}

test "sched m6: depth/priority of the binary carry and k-ary plans; critical leaves = carry order for r1" {
    const plan = try Plan.init(17);
    try std.testing.expectEqual(@as(u8, 0), plan.depth[plan.root]);
    for (plan.nodes[0..plan.count], 0..) |node, id| {
        for (node.kids()) |kid| try std.testing.expectEqual(plan.depth[id] + 1, plan.depth[kid]);
        if (node.isLeaf()) try std.testing.expect(plan.priority(id) % 2 == 1);
    }
    // 17 = 16 + 1: leaves 0..15 sit 5 below the root, leaf 16 one below.
    try std.testing.expectEqual(@as(u8, 5), plan.depth[0]);
    try std.testing.expectEqual(@as(u8, 1), plan.depth[plan.count - 2]);
    for (2..5) |arity| for (1..257) |n| {
        const p = try Plan.initArity(n, arity);
        var q = try Queue.initPolicy(&p, 2, p.minimumLimit(2) + 8, .critical);
        var m = try Queue.initPolicy(&p, 2, p.minimumLimit(2) + 8, .m5);
        // Leaf depth never increases with the ordinal (carry finalization),
        // so the critical leaf order equals the M5 order for every plan.
        var last: u8 = 255;
        for (p.nodes[0..p.count], 0..) |node, id| if (node.isLeaf()) {
            try std.testing.expect(p.depth[id] <= last);
            last = p.depth[id];
        };
        for (0..@min(n, 4)) |_| try std.testing.expectEqual(try m.takeFiltered(true), try q.takeFiltered(true));
    };
}

test "sched m6: gated (streaming) leaves never deadlock and keep admission bounded under adversarial completion" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    for ([_]usize{ 2, 4 }) |arity| for (1..5) |lanes| for ([_]usize{ 1, 2, 5, 11, 17, 33, 64, 100, 256 }) |n| for (0..4) |trial| {
        const plan = try Plan.initArity(n, arity);
        const limit = plan.minimumLimit(lanes) + trial;
        var q = try Queue.initPolicy(&plan, lanes, limit, if (trial % 2 == 0) .critical else .m5);
        q.closeAllLeaves();
        var opened: usize = 0;
        var active: std.ArrayList(usize) = .empty;
        defer active.deinit(std.testing.allocator);
        var concurrency = lanes + trial;
        if (concurrency == 0) concurrency = 1;
        while (q.completed < plan.count) {
            // Native workers finish in a random order (stage 2 of a lane pool).
            if (opened < n and (active.items.len == 0 or random.boolean())) {
                var pick = random.uintLessThan(usize, n);
                while (!q.closed.isSet(pick)) pick = (pick + 1) % n;
                q.openLeaf(pick);
                opened += 1;
            }
            while (active.items.len < concurrency) {
                const next = try q.takeFiltered(true) orelse break;
                try std.testing.expect(!plan.nodes[next].isLeaf() or opened > 0);
                try active.append(std.testing.allocator, next);
            }
            if (active.items.len == 0) {
                try std.testing.expect(opened < n);
                continue;
            }
            const id = active.swapRemove(random.uintLessThan(usize, active.items.len));
            q.complete(id);
            try std.testing.expect(q.live + q.active <= q.limit);
        }
        try std.testing.expectEqual(@as(usize, 1), q.live);
    };
}

test "sched m6: policy env parse" {
    try std.testing.expectEqual(Policy.m5, try Policy.fromEnv());
}
