//! Bounded CPU-only pool ownership for the existing recursive DAG. No proof
//! identity, transcript or verifier policy depends on this operational choice.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Pools = engine.work_pool;
const Budget = engine.host_budget_allocator.SharedHostBudget;

pub fn fromEnv(a: std.mem.Allocator) !?usize {
    const text = std.process.getEnvVarOwned(a, "STWO_RV64_RECURSION_CPU_LANES") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer a.free(text);
    return try parseCount(text);
}
fn parseCount(text: []const u8) !usize {
    const count = try std.fmt.parseUnsigned(usize, text, 10);
    if (count < 2 or count > 4) return error.InvalidCpuRecursionLanes;
    return count;
}
pub const Options = struct {
    lanes: usize,
    workers: usize,
    stack_size: usize,
    pub fn validate(self: Options) !void {
        if (self.lanes < 2 or self.lanes > 4) return error.InvalidCpuRecursionLanes;
        if (self.workers < self.lanes * 2 or self.workers > Pools.MAX_WORKERS) return error.InsufficientCpuRecursionWorkers;
        if (self.stack_size == 0) return error.InvalidCpuRecursionStack;
    }
    pub fn laneWorkers(self: Options, index: usize) usize {
        std.debug.assert(index < self.lanes);
        return self.workers / self.lanes + @intFromBool(index < self.workers % self.lanes);
    }
};
/// Whole-proof worker admission. Folds take the complete caller pool; waiting
/// folds block new leaves so they cannot starve behind a stream of small jobs.
pub const WorkerGate = struct {
    mutex: std.Thread.Mutex = .{},
    condition: std.Thread.Condition = .{},
    total: usize,
    active: usize = 0,
    exclusive_waiters: usize = 0,
    fn available(self: *const WorkerGate, workers: usize) bool {
        return self.active + workers <= self.total and (workers == self.total or self.exclusive_waiters == 0);
    }
    pub fn enter(self: *WorkerGate, workers: usize) void {
        std.debug.assert(workers > 0 and workers <= self.total);
        self.mutex.lock();
        defer self.mutex.unlock();
        const exclusive = workers == self.total;
        if (exclusive) self.exclusive_waiters += 1;
        while (!self.available(workers)) self.condition.wait(&self.mutex);
        if (exclusive) self.exclusive_waiters -= 1;
        self.active += workers;
    }
    pub fn leave(self: *WorkerGate, workers: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.active >= workers);
        self.active -= workers;
        self.condition.broadcast();
    }
};
/// Stable heap address: WorkPool cannot be moved after helper threads start.
/// Coordinator and helper stacks are charged before spawning any thread.
pub const Owner = struct {
    allocator: std.mem.Allocator,
    options: Options,
    pools: [4]Pools.WorkPool = @splat(.{}),
    initialized: usize = 0,
    stacks: Budget.ExternalReservation,
    gate: WorkerGate,
    pub fn create(budget: *Budget, options: Options) !*Owner {
        try options.validate();
        const a = budget.allocator();
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .options = options, .stacks = Budget.ExternalReservation.empty(), .gate = .{ .total = options.workers } };
        errdefer self.destroy();
        self.stacks = try budget.reserveExternal(try std.math.add(usize, try std.math.mul(usize, 2 * options.workers - options.lanes - 1, options.stack_size), try std.math.mul(usize, options.lanes, 8 << 20)));
        for (self.pools[0..options.lanes], 0..) |*pool, i| {
            try pool.initInPlaceWithOptions(.{ .worker_count = options.laneWorkers(i), .stack_size = options.stack_size, .backing_allocator = a });
            self.initialized += 1;
        }
        return self;
    }
    pub fn destroy(self: *Owner) void {
        for (self.pools[0..self.initialized]) |*pool| pool.deinit();
        self.stacks.deinit();
        self.allocator.destroy(self);
    }
};

test "OM31 native PCS CPU recursion lane admission and worker partition are bounded" {
    for (2..5) |count| {
        var text: [2]u8 = undefined;
        try std.testing.expectEqual(count, try parseCount(try std.fmt.bufPrint(&text, "{d}", .{count})));
        for (count * 2..Pools.MAX_WORKERS + 1) |workers| {
            const options = Options{ .lanes = count, .workers = workers, .stack_size = 1 << 20 };
            try options.validate();
            var sum: usize = 0;
            for (0..count) |i| sum += options.laneWorkers(i);
            try std.testing.expectEqual(workers, sum);
        }
    }
    for ([_][]const u8{ "0", "1", "5", "99" }) |text| try std.testing.expectError(error.InvalidCpuRecursionLanes, parseCount(text));
    try std.testing.expectError(error.InvalidCharacter, parseCount("two"));
    try std.testing.expectError(error.InsufficientCpuRecursionWorkers, (Options{ .lanes = 2, .workers = 3, .stack_size = 1 }).validate());
}
test "OM31 native PCS CPU lane refused stack admission releases the partial owner" {
    const budget = try Budget.create(std.testing.allocator, 4 << 20);
    defer budget.destroy();
    const before = budget.snapshot();
    try std.testing.expectError(error.OutOfMemory, Owner.create(budget, .{ .lanes = 2, .workers = 4, .stack_size = 1 << 20 }));
    const after = budget.snapshot();
    try std.testing.expect(after.exceeded);
    try std.testing.expectEqual(before.live_bytes, after.live_bytes);
    try std.testing.expectEqual(before.external_live_bytes, after.external_live_bytes);
}
test "OM31 native PCS CPU lane pools retain stable ownership and release all reservations" {
    const budget = try Budget.create(std.testing.allocator, 64 << 20);
    defer budget.destroy();
    const before = budget.snapshot();
    {
        const owner = try Owner.create(budget, .{ .lanes = 2, .workers = 7, .stack_size = 1 << 20 });
        defer owner.destroy();
        try std.testing.expectEqual(@as(usize, 4), owner.pools[0].workerCount());
        try std.testing.expectEqual(@as(usize, 3), owner.pools[1].workerCount());
        try std.testing.expectEqual(@as(usize, 27 << 20), budget.snapshot().external_live_bytes);
    }
    const after = budget.snapshot();
    try std.testing.expectEqual(before.live_bytes, after.live_bytes);
    try std.testing.expectEqual(before.external_live_bytes, after.external_live_bytes);
}

test "OM31 native PCS CPU fold admission drains leaves without reducing fold workers" {
    var gate = WorkerGate{ .total = 16 };
    gate.enter(8);
    gate.enter(8);
    try std.testing.expect(!gate.available(1));
    gate.leave(8);
    gate.exclusive_waiters = 1;
    try std.testing.expect(!gate.available(8));
    try std.testing.expect(!gate.available(16));
    gate.leave(8);
    try std.testing.expect(gate.available(16));
    gate.exclusive_waiters = 0;
    gate.enter(16);
    try std.testing.expectEqual(@as(usize, 16), gate.active);
    gate.leave(16);
    try std.testing.expectEqual(@as(usize, 0), gate.active);
}
