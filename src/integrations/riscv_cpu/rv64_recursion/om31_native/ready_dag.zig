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
        if (self.failure != null or self.completed == self.plan.count) return null;
        // A newly generated parent needs an additional slot until its two
        // children can be retired. Leaves always leave that slot available.
        if (self.live + self.active < self.limit) {
            for (self.plan.nodes[0..self.plan.count], 0..) |node, i| {
                if (self.status[i] != .pending or node.left == null) continue;
                if (self.status[node.left.?] == .done and self.status[node.right.?] == .done) return self.start(i);
            }
        }
        if (self.live + self.active + 1 < self.limit) {
            for (self.plan.nodes[0..self.plan.count], 0..) |node, i| {
                if (self.status[i] == .pending and node.left == null) return self.start(i);
            }
        }
        if (self.active == 0) return error.RecursiveReadyDeadlock;
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
