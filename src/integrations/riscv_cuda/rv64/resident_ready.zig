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
const Service = @import("pcs_native.zig");
pub const Context = struct {
    allocator: std.mem.Allocator,
    contexts: []Outer = &.{},
    services: []Service.Context = &.{},
    initialized_services: usize = 0,
    // Mutable returned-column lists, timing/geometry caches and stage mutexes
    // belong to a recursion lane. The physical session and its scoped lease
    // registry remain shared, so the device cap is charged exactly once.
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
    /// Physical device of every lane, in lane order (sched M6: up to 2 lanes,
    /// i.e. concurrent outer proofs, per device; STWO_RV64_RECURSION_LANES_PER_DEVICE).
    physical: []u32 = &.{},
    pub fn create(a: std.mem.Allocator, devices: *Pool, ids: []const u32, total: usize, pending: usize) !*Context {
        return createWithDeviceFixed(a, devices, ids, total, pending, false);
    }
    pub fn createWithDeviceFixed(a: std.mem.Allocator, devices: *Pool, ids: []const u32, total: usize, pending: usize, device_fixed: bool) !*Context {
        _ = try Policy.workers(.ready_candidate, ids, total, pending);
        if (devices.devices.len != ids.len) return error.InvalidResidentReadyAdmission;
        const per_device = try Policy.lanesPerDevice();
        const lane_count = ids.len * per_device;
        if (lane_count > 4 or total < lane_count) return error.InvalidResidentReadyAdmission;
        var counts: [4]usize = @splat(0);
        for (0..lane_count) |i| counts[i] = total / lane_count + @intFromBool(i < total % lane_count);
        const owner = try CPU.rv64_recursion_budget.require(Engine.host_budget_allocator.SharedHostBudget, a);
        const self = try a.create(Context);
        self.* = .{ .allocator = a, .total_workers = total, .pending = pending };
        errdefer self.deinit();
        // These pools remain alive across native production as well as roots.
        self.helpers = try owner.reserveExternal(try std.math.mul(usize, total - lane_count, Policy.helper_stack_bytes));
        self.contexts = try a.alloc(Outer, lane_count);
        const separate = if (std.posix.getenv("STWO_RV64_RECURSION_SESSIONS")) |value| std.mem.eql(u8, value, "1") else false;
        if (separate) self.services = try a.alloc(Service.Context, lane_count);
        self.traces = try a.alloc(TraceCommit.Context, lane_count);
        self.compositions = try a.alloc(Composition.Context, lane_count);
        self.pools = try a.alloc(Engine.work_pool.WorkPool, lane_count);
        self.lanes = try a.alloc(Execute.Lane, lane_count);
        self.physical = try a.alloc(u32, lane_count);
        // Lane order: device-major round robin (lane i -> device i % n), so
        // with one lane per device the M5 lane/device mapping is unchanged.
        for (0..lane_count) |i| {
            const device = &devices.devices[i % ids.len];
            const id = ids[i % ids.len];
            const service = if (separate) blk: {
                self.services[i] = try device.native.createSibling(a, id);
                self.initialized_services += 1;
                break :blk &self.services[i];
            } else &device.native;
            self.physical[i] = id;
            self.pools[i] = .{};
            try self.pools[i].initInPlaceWithOptions(.{ .worker_count = counts[i], .stack_size = Policy.helper_stack_bytes, .backing_allocator = a });
            self.initialized_pools += 1;
            self.traces[i] = try TraceCommit.Context.init(service);
            self.traces[i].admission_domain = .recursion_node;
            try self.traces[i].registerAdmissionCoverage();
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
    pub fn beginBlock(self: *Context, identity: [32]u8, immutable_bytes: u64, max_scopes: usize) !void {
        var initialized: usize = 0;
        errdefer for (self.services[0..initialized]) |*service| service.endBlock(identity) catch {};
        for (self.services) |*service| {
            try service.beginBlock(identity, .{ .device_bytes = service.byte_cap, .immutable_bytes = immutable_bytes, .max_scopes = max_scopes });
            initialized += 1;
        }
    }
    pub fn endBlock(self: *Context, identity: [32]u8) !void {
        for (self.services) |*service| try service.endBlock(identity);
    }
    pub fn deinit(self: *Context) void {
        const a = self.allocator;
        // The DAG joins its coordinators first; also join every helper pool
        // before retiring factory metadata, including partial init failures.
        for (self.pools[0..self.initialized_pools]) |*pool| pool.deinit();
        for (self.contexts[0..self.initialized_contexts]) |*context| context.deinit();
        for (self.traces[0..self.initialized_traces]) |*trace| trace.deinit();
        for (self.compositions[0..self.initialized_compositions]) |*composition| composition.deinit();
        for (self.services[0..self.initialized_services]) |*service| service.deinit();
        self.helpers.deinit();
        a.free(self.traces);
        a.free(self.compositions);
        a.free(self.lanes);
        a.free(self.physical);
        a.free(self.pools);
        a.free(self.contexts);
        a.free(self.services);
        a.destroy(self);
    }
};
