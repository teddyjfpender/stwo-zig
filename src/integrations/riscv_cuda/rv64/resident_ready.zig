//! Persistent per-physical-device recursion contexts and already charged pools.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Engine = @import("stwo_prover_engine");
const Execute = CPU.rv64_om31_execution_wrap;
const Pool = @import("resident_pool.zig").Pool;
const Outer = @import("outer_source.zig").Context;
const Policy = @import("resident_ready_policy.zig");
pub const Context = struct {
    allocator: std.mem.Allocator,
    contexts: []Outer = &.{},
    pools: []Engine.work_pool.WorkPool = &.{},
    lanes: []Execute.Lane = &.{},
    initialized_contexts: usize = 0,
    initialized_pools: usize = 0,
    helpers: Engine.host_budget_allocator.SharedHostBudget.ExternalReservation = .{},
    total_workers: usize,
    pending: usize,
    pub fn create(a: std.mem.Allocator, devices: *Pool, ids: []const u32, total: usize, pending: usize) !*Context {
        const counts = try Policy.workers(.ready_candidate, ids, total, pending);
        if (devices.devices.len != ids.len) return error.InvalidResidentReadyAdmission;
        const owner = try CPU.rv64_recursion_budget.require(Engine.host_budget_allocator.SharedHostBudget, a);
        const self = try a.create(Context);
        self.* = .{ .allocator = a, .total_workers = total, .pending = pending };
        errdefer self.deinit();
        // These pools remain alive across native production as well as roots.
        self.helpers = try owner.reserveExternal(try std.math.mul(usize, total - ids.len, Policy.helper_stack_bytes));
        self.contexts = try a.alloc(Outer, ids.len);
        self.pools = try a.alloc(Engine.work_pool.WorkPool, ids.len);
        self.lanes = try a.alloc(Execute.Lane, ids.len);
        for (devices.devices, ids, 0..) |*device, id, i| {
            self.pools[i] = .{};
            try self.pools[i].initInPlaceWithOptions(.{ .worker_count = counts[i], .stack_size = Policy.helper_stack_bytes, .backing_allocator = a });
            self.initialized_pools += 1;
            self.contexts[i] = try Outer.init(a, &device.native, &device.trace, &device.composition);
            self.initialized_contexts += 1;
            self.lanes[i] = .{ .physical_device = id, .factory = try self.contexts[i].factoryForTraceOnly(), .pool = &self.pools[i] };
        }
        try Execute.validateLanes(self.options());
        return self;
    }
    pub fn options(self: *Context) Execute.ParallelOptions {
        return .{ .lanes = self.lanes, .pool_worker_budget = self.total_workers, .max_pending_authorities = self.pending, .pool_stack_reservation = &self.helpers };
    }
    pub fn deinit(self: *Context) void {
        const a = self.allocator;
        // The DAG joins its coordinators first; also join every helper pool
        // before retiring factory metadata, including partial init failures.
        for (self.pools[0..self.initialized_pools]) |*pool| pool.deinit();
        for (self.contexts[0..self.initialized_contexts]) |*context| context.deinit();
        self.helpers.deinit();
        a.free(self.lanes);
        a.free(self.pools);
        a.free(self.contexts);
        a.destroy(self);
    }
};
