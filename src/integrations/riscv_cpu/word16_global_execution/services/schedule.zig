//! Bounded independent worker scheduling. Each lane owns a stable intra-proof
//! pool; no helper implicitly creates a process-global pool. Phase barriers
//! belong to the caller and always join every thread before consuming results.
const std = @import("std");
const Pool = @import("stwo_prover_engine").work_pool;
pub const Policy = struct {
    lanes: u8 = 1,
    workers_per_lane: u8 = 8,
    pub fn validate(self: Policy) !void {
        if (self.lanes == 0 or self.lanes > 2 or self.workers_per_lane == 0 or self.workers_per_lane > 32 or @as(u32, self.lanes) * self.workers_per_lane > 32) return error.InvalidServiceSchedule;
    }
};
/// The context's indexed slots must be disjoint and allocator thread-safe.
/// Default lane1 keeps the caller's already bound pool and old execution path.
pub fn run(comptime Context: type, a: std.mem.Allocator, context: *Context, count: usize, policy: Policy, comptime execute: fn (*Context, usize) anyerror!void) !void {
    return runOrdered(Context, a, context, count, null, policy, execute);
}
/// Rejects anything but a permutation of [0, count): every slot runs once.
pub fn validateOrder(a: std.mem.Allocator, count: usize, order: []const usize) !void {
    if (order.len != count) return error.InvalidServiceDispatchOrder;
    const seen = try a.alloc(bool, count);
    defer a.free(seen);
    @memset(seen, false);
    for (order) |slot| {
        if (slot >= count or seen[slot]) return error.InvalidServiceDispatchOrder;
        seen[slot] = true;
    }
}
/// Same as `run`, but the k-th dispatched task executes slot `order[k]`.
/// Only the execution order changes; `execute` still receives the stable slot
/// index, so slot<->spec mapping and all outputs are dispatch-order invariant.
pub fn runOrdered(comptime Context: type, a: std.mem.Allocator, context: *Context, count: usize, order: ?[]const usize, policy: Policy, comptime execute: fn (*Context, usize) anyerror!void) !void {
    try policy.validate();
    if (order) |o| try validateOrder(a, count, o);
    if (count == 0) return;
    if (policy.lanes == 1 or count == 1) {
        for (0..count) |index| try execute(context, if (order) |o| o[index] else index);
        return;
    }
    const Shared = struct {
        context: *Context,
        count: usize,
        order: ?[]const usize,
        workers_per_lane: usize,
        allocator: std.mem.Allocator,
        next: std.atomic.Value(usize) = .init(0),
        stop: std.atomic.Value(bool) = .init(false),
        errors: []?anyerror,
        lane_errors: [2]?anyerror = @splat(null),
        fn lane(self: *@This(), ordinal: usize) void {
            var pool: Pool.WorkPool = .{};
            pool.initInPlaceWithOptions(.{ .worker_count = self.workers_per_lane, .stack_size = 1024 * 1024, .backing_allocator = self.allocator }) catch |err| {
                self.lane_errors[ordinal] = err;
                self.stop.store(true, .release);
                return;
            };
            defer pool.deinit();
            var binding = Pool.ScopedPoolBinding.init(&pool) catch |err| {
                self.lane_errors[ordinal] = err;
                self.stop.store(true, .release);
                return;
            };
            defer binding.deinit();
            while (!self.stop.load(.acquire)) {
                const ticket = self.next.fetchAdd(1, .monotonic);
                if (ticket >= self.count) return;
                const index = if (self.order) |o| o[ticket] else ticket;
                execute(self.context, index) catch |err| {
                    self.errors[index] = err;
                    self.stop.store(true, .release);
                    return;
                };
            }
        }
    };
    const errors = try a.alloc(?anyerror, count);
    defer a.free(errors);
    @memset(errors, null);
    var shared = Shared{ .context = context, .count = count, .order = order, .workers_per_lane = policy.workers_per_lane, .allocator = a, .errors = errors };
    var threads: [2]std.Thread = undefined;
    var spawned: usize = 0;
    // Spawn failure also joins every started task before caller cleanup.
    errdefer {
        shared.stop.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (0..@min(count, policy.lanes)) |ordinal| {
        threads[ordinal] = try std.Thread.spawn(.{}, Shared.lane, .{ &shared, ordinal });
        spawned += 1;
    }
    for (threads[0..spawned]) |thread| thread.join();
    spawned = 0;
    for (shared.lane_errors) |err| if (err) |failure| return failure;
    for (errors) |err| if (err) |failure| return failure;
}
