//! Persistent per-physical-device recursion contexts and already charged pools.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Engine = @import("stwo_prover_engine");
const Execute = CPU.rv64_om31_execution_wrap;
const Pool = @import("resident_pool.zig").Pool;
const Outer = @import("outer_source.zig").Context;
const Policy = @import("resident_ready_policy.zig");
const TraceCommit = @import("trace_commit.zig");
const Composition = @import("resident_composition.zig");
pub const Context = struct {
    allocator: std.mem.Allocator,
    contexts: []Outer = &.{},
    // Per-device recursion metadata and helper pools borrow the native
    // session and scoped leases owned by Pool.
    traces: []TraceCommit.Context = &.{},
    compositions: []Composition.Context = &.{},
    initialized_traces: usize = 0,
    initialized_compositions: usize = 0,
    pools: []Engine.work_pool.WorkPool = &.{},
    lanes: []Execute.Lane = &.{},
    initialized_contexts: usize = 0,
    initialized_pools: usize = 0,
    helpers: Engine.host_budget_allocator.SharedHostBudget.ExternalReservation = .{},
    total_workers: usize,
    pending: usize,
    /// One recursion lane per physical device, in the admitted device order.
    physical: []u32 = &.{},
    pub fn create(a: std.mem.Allocator, devices: *Pool, ids: []const u32, total: usize, pending: usize) !*Context {
        return createWithDeviceFixed(a, devices, ids, total, pending, false);
    }
    pub fn createWithDeviceFixed(a: std.mem.Allocator, devices: *Pool, ids: []const u32, total: usize, pending: usize, device_fixed: bool) !*Context {
        const counts = try Policy.workers(.ready_candidate, ids, total, pending);
        if (devices.devices.len != ids.len) return error.InvalidResidentReadyAdmission;
        const lane_count = ids.len;
        const owner = try CPU.rv64_recursion_budget.require(Engine.host_budget_allocator.SharedHostBudget, a);
        const self = try a.create(Context);
        self.* = .{ .allocator = a, .total_workers = total, .pending = pending };
        errdefer self.deinit();
        // These pools remain alive across native production as well as roots.
        self.helpers = try owner.reserveExternal(try std.math.mul(usize, total - lane_count, Policy.helper_stack_bytes));
        self.contexts = try a.alloc(Outer, lane_count);
        self.traces = try a.alloc(TraceCommit.Context, lane_count);
        self.compositions = try a.alloc(Composition.Context, lane_count);
        self.pools = try a.alloc(Engine.work_pool.WorkPool, lane_count);
        self.lanes = try a.alloc(Execute.Lane, lane_count);
        self.physical = try a.alloc(u32, lane_count);
        for (0..lane_count) |i| {
            const device = &devices.devices[i];
            const id = ids[i];
            const service = &device.native;
            self.physical[i] = id;
            self.pools[i] = .{};
            try self.pools[i].initInPlaceWithOptions(.{ .worker_count = counts[i], .stack_size = Policy.helper_stack_bytes, .backing_allocator = a });
            self.initialized_pools += 1;
            self.traces[i] = try TraceCommit.Context.init(service);
            self.traces[i].admission_domain = .recursion_node;
            self.initialized_traces += 1;
            self.compositions[i] = try Composition.Context.initNumerical(a, service);
            self.initialized_compositions += 1;
            self.contexts[i] = try Outer.init(a, service, &self.traces[i], &self.compositions[i]);
            self.initialized_contexts += 1;
            self.lanes[i] = .{ .physical_device = id, .factory = if (device_fixed) try self.contexts[i].factoryWithDeviceFixed() else try self.contexts[i].factoryForTraceOnly(), .pool = &self.pools[i] };
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
        for (self.traces[0..self.initialized_traces]) |*trace| trace.deinit();
        for (self.compositions[0..self.initialized_compositions]) |*composition| composition.deinit();
        self.helpers.deinit();
        a.free(self.traces);
        a.free(self.compositions);
        a.free(self.lanes);
        a.free(self.physical);
        a.free(self.pools);
        a.free(self.contexts);
        a.destroy(self);
    }
};
