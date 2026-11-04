//! Exact serial node identities with completion-order-independent ready dispatch.
//! A successful completion means verified AND durably published. A parent keeps
//! both children live until then. Output slots include active wide graphs.
const std = @import("std");
pub const max_leaves = 256;
pub const max_nodes = 2 * max_leaves - 1;
pub const Node = struct { first_leaf: usize, leaf_count: usize, left: ?usize = null, right: ?usize = null };
pub const Plan = struct {
    nodes: [max_nodes]Node = undefined,
    count: usize = 0,
    root: usize = 0,
    pub fn init(leaves: usize) !Plan {
        if (leaves == 0 or leaves > max_leaves) return error.InvalidRecursionLeaves;
        var self: Plan = .{};
        var stack = [_]?usize{null} ** 9;
        for (0..leaves) |ordinal| {
            var current = self.append(.{ .first_leaf = ordinal, .leaf_count = 1 });
            var level: usize = 0;
            while (stack[level]) |left| : (level += 1) {
                current = self.parent(left, current);
                stack[level] = null;
            }
            stack[level] = current;
        }
        var root: ?usize = null;
        for (stack) |entry| if (entry) |left| {
            root = if (root) |right| self.parent(left, right) else left;
        };
        self.root = root.?;
        std.debug.assert(self.count == 2 * leaves - 1);
        return self;
    }
    fn append(self: *Plan, node: Node) usize {
        const id = self.count;
        self.nodes[id] = node;
        self.count += 1;
        return id;
    }
    fn parent(self: *Plan, left: usize, right: usize) usize {
        const l = self.nodes[left];
        const r = self.nodes[right];
        std.debug.assert(l.first_leaf + l.leaf_count == r.first_leaf);
        return self.append(.{ .first_leaf = l.first_leaf, .leaf_count = l.leaf_count + r.leaf_count, .left = left, .right = right });
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
pub const Queue = struct {
    plan: *const Plan,
    status: [max_nodes]Status = @splat(.pending),
    limit: usize,
    live: usize = 0,
    active: usize = 0,
    completed: usize = 0,
    peak: usize = 0,
    failure: ?struct { node: usize, err: anyerror } = null,
    pub fn init(plan: *const Plan, lanes: usize, limit: usize) !Queue {
        if (lanes == 0 or lanes > 4 or limit < 9 + 2 * lanes) return error.InvalidRecursionAdmission;
        return .{ .plan = plan, .limit = limit };
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
            for (self.plan.nodes[0..self.plan.count], 0..) |node, i| {
                if (self.status[i] != .pending or node.left == null) continue;
                if (self.status[node.left.?] == .done and self.status[node.right.?] == .done) return self.start(i);
            }
        }
        if (leaves and self.live + self.active + 1 < self.limit) {
            for (self.plan.nodes[0..self.plan.count], 0..) |node, i| {
                if (self.status[i] == .pending and node.left == null) return self.start(i);
            }
        }
        if (self.active == 0 and leaves) return error.RecursiveReadyDeadlock;
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
        const node = self.plan.nodes[id];
        if (node.left) |left| {
            const right = node.right.?;
            std.debug.assert(self.status[left] == .done and self.status[right] == .done);
            self.status[left] = .retired;
            self.status[right] = .retired;
            self.live -= 2;
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
    const expected = [_]Node{
        .{ .first_leaf = 0, .leaf_count = 1 },                        .{ .first_leaf = 1, .leaf_count = 1 },
        .{ .first_leaf = 0, .leaf_count = 2, .left = 0, .right = 1 }, .{ .first_leaf = 2, .leaf_count = 1 },
        .{ .first_leaf = 3, .leaf_count = 1 },                        .{ .first_leaf = 2, .leaf_count = 2, .left = 3, .right = 4 },
        .{ .first_leaf = 0, .leaf_count = 4, .left = 2, .right = 5 }, .{ .first_leaf = 4, .leaf_count = 1 },
        .{ .first_leaf = 0, .leaf_count = 5, .left = 6, .right = 7 },
    };
    try std.testing.expectEqualDeep(&expected, plan.nodes[0..plan.count]);
    for (1..257) |n| {
        const p = try Plan.init(n);
        try std.testing.expectEqual(n, p.nodes[p.root].leaf_count);
        for (p.nodes[0..p.count], 0..) |node, id| if (node.left == null) {
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
        const node = self.dispatch.queue.plan.nodes[id];
        if (node.left) |left| {
            const right = node.right.?;
            std.debug.assert(self.durable[left] and self.durable[right]);
            std.debug.assert(self.retained[left] and self.retained[right]);
            self.retained[left] = false;
            self.retained[right] = false;
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
