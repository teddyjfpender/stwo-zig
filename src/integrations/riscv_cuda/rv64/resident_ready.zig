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
const Native = @import("pcs_native.zig");
/// Native-owner fan-out publishes an independent per-physical-device gate.
/// Standalone recursion-only builds use the native composition mutex, which
/// already excludes that device's native composition callback.
fn physicalGate(devices: *Pool, physical: usize) *std.Thread.Mutex {
    if (comptime @hasField(Pool, "phase_gates")) return &devices.phase_gates[physical];
    return &devices.devices[physical].composition.mutex;
}
pub const Context = struct {
    allocator: std.mem.Allocator,
    contexts: []Outer = &.{},
    // Mutable returned-column lists, timing/geometry caches and stage mutexes
    // belong to a recursion lane. The physical session and its scoped lease
    // registry remain shared, so the device cap is charged exactly once.
    traces: []TraceCommit.Context = &.{},
    native_sessions: []Native.Context = &.{},
    initialized_native_sessions: usize = 0,
    lanes_per_device: usize = 1,
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
        const lane_sessions = try Policy.laneSessions();
        const lane_count = ids.len * per_device;
        if (lane_count > 4 or total < lane_count) return error.InvalidResidentReadyAdmission;
        var counts: [4]usize = @splat(0);
        for (0..lane_count) |i| counts[i] = total / lane_count + @intFromBool(i < total % lane_count);
        const owner = try CPU.rv64_recursion_budget.require(Engine.host_budget_allocator.SharedHostBudget, a);
        const self = try a.create(Context);
        self.* = .{ .allocator = a, .total_workers = total, .pending = pending, .lanes_per_device = per_device };
        errdefer self.deinit();
        // These pools remain alive across native production as well as roots.
        self.helpers = try owner.reserveExternal(try std.math.mul(usize, total - lane_count, Policy.helper_stack_bytes));
        self.contexts = try a.alloc(Outer, lane_count);
        if (lane_sessions) self.native_sessions = try a.alloc(Native.Context, lane_count);
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
            self.physical[i] = id;
            self.pools[i] = .{};
            try self.pools[i].initInPlaceWithOptions(.{ .worker_count = counts[i], .stack_size = Policy.helper_stack_bytes, .backing_allocator = a });
            self.initialized_pools += 1;
            const native = if (lane_sessions) blk: {
                self.native_sessions[i] = try Native.Context.initBorrowedLibrary(&device.native.library, id, device.native.byte_cap);
                self.initialized_native_sessions += 1;
                self.native_sessions[i].phase_mutex = physicalGate(devices, i % ids.len);
                device.native.phase_mutex = physicalGate(devices, i % ids.len);
                if (comptime @hasField(Pool, "phase_gates")) {
                    device.composition.phase_mutex = physicalGate(devices, i % ids.len);
                    if (comptime @hasField(@TypeOf(device.gkr), "phase_mutex")) device.gkr.phase_mutex = physicalGate(devices, i % ids.len);
                }
                break :blk &self.native_sessions[i];
            } else &device.native;
            self.traces[i] = try TraceCommit.Context.init(native);
            self.initialized_traces += 1;
            self.compositions[i] = try Composition.Context.initNumerical(a, native);
            self.initialized_compositions += 1;
            if (lane_sessions) self.compositions[i].phase_mutex = physicalGate(devices, i % ids.len);
            self.contexts[i] = try Outer.init(a, native, &self.traces[i], &self.compositions[i]);
            self.initialized_contexts += 1;
            if (lane_sessions) self.contexts[i].phase_mutex = physicalGate(devices, i % ids.len);
            self.lanes[i] = .{ .physical_device = id, .factory = if (device_fixed) try self.contexts[i].factoryWithDeviceFixed() else try self.contexts[i].factoryForTraceOnly(), .pool = &self.pools[i] };
        }
        try Execute.validateLanes(self.options());
        return self;
    }
    /// Every private lane session audits its own namespace. The CUDA arena is
    /// still process-wide per physical GPU, so private caps cannot enlarge the
    /// physical device allocation. Split the outer immutable budget per lane.
    pub fn beginBlock(self: *Context, identity: [32]u8, immutable_bytes: u64, max_scopes: usize) !void {
        for (self.native_sessions[0..self.initialized_native_sessions]) |*native| try native.beginBlock(identity, .{ .device_bytes = native.byte_cap, .immutable_bytes = immutable_bytes / self.lanes_per_device, .max_scopes = max_scopes });
    }
    pub fn endBlock(self: *Context, identity: [32]u8) !void {
        for (self.native_sessions[0..self.initialized_native_sessions]) |*native| try native.endBlock(identity);
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
        for (self.native_sessions[0..self.initialized_native_sessions]) |*native| native.deinit();
        self.helpers.deinit();
        a.free(self.native_sessions);
        a.free(self.traces);
        a.free(self.compositions);
        a.free(self.lanes);
        a.free(self.physical);
        a.free(self.pools);
        a.free(self.contexts);
        a.destroy(self);
    }
};
