//! Bounded GPU MAIN/P8 replay across the shared-challenge manifest barrier.
//! Retains compact capture only; original MAIN root and authenticated P8 digest
//! are checked before the replayed columns can enter the physical proof.
//!
//! M6 (native-stream): replay is OVERFLOW only. The first `retain_per_device`
//! CPU workers live on a device keep their stage-one MAIN and binding resident
//! across the barrier (exactly the retained, non-replay path: park/restore are
//! no-ops and no compact host copy is made); only workers beyond that bound
//! park and replay. Which path a worker takes is operational: a replayed MAIN
//! must reproduce the original root (`expected_main_root`), so proof bytes are
//! the same either way. The bound caps retained device inventory at what the
//! dev blocks hold (24628607: 4 CPU segments on GPU0), independent of block size.
//! `STWO_RV64_GPU_REPLAY_RETAIN_PER_DEVICE=N` (default 4; 0 = M5 replay-all).
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Interface = CPU.rv64_gkr_cpu_replay;
const Request = CPU.rv64_device_source_stage.Request;
const Worker = CPU.rv64_gkr_cpu_worker.CpuWorker;
const D = CPU.rv64_device_pcs;
const Child = CPU.rv64_gkr_child;
pub const Context = struct {
    service: *@import("pcs_native.zig").Context,
    source: *@import("device_source.zig").Context,
    trace: *@import("trace_commit.zig").Context,
    compact_cap: usize = 24 << 30,
    compact_bytes: usize = 0,
    /// Resolved from the environment on first use (null = not yet read).
    retain_per_device: ?usize = null,
    retained_live: usize = 0,
    retained_total: usize = 0,
    replayed_total: usize = 0,
    mutex: std.Thread.Mutex = .{},
    pub const default_retain: usize = 4;
    pub fn retainLimitFromEnv() !usize {
        const text = std.posix.getenv("STWO_RV64_GPU_REPLAY_RETAIN_PER_DEVICE") orelse return default_retain;
        const value = std.fmt.parseInt(usize, text, 10) catch return error.InvalidReplayRetainLimit;
        if (value > 64) return error.InvalidReplayRetainLimit;
        return value;
    }
    pub fn deinit(self: *Context) void {
        std.debug.assert(self.compact_bytes == 0 and self.retained_live == 0);
        self.* = undefined;
    }
    pub fn stage(self: *Context) Interface.Stage {
        return .{ .context = self, .estimate = estimate, .prepare = prepare };
    }
    fn estimate(_: *anyopaque, request: Request) !usize {
        const captured = try Interface.Capture.bytes(request.native);
        return std.math.add(usize, captured, std.mem.sliceAsBytes(request.advice.events[request.ordinal]).len);
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, request: Request) !Interface.Owner {
        const self: *Context = @ptrCast(@alignCast(raw));
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            const limit = self.retain_per_device orelse blk: {
                const value = try retainLimitFromEnv();
                self.retain_per_device = value;
                break :blk value;
            };
            if (self.retained_live < limit) {
                self.retained_live += 1;
                self.retained_total += 1;
                const owner = a.create(Retained) catch |err| {
                    self.retained_live -= 1;
                    self.retained_total -= 1;
                    return err;
                };
                owner.* = .{ .allocator = a, .backend = self, .ordinal = request.scope.ordinal };
                return .{ .context = owner, .retained_host_bytes = 0, .park = Retained.park, .restore = Retained.restore, .release = Retained.release };
            }
            self.replayed_total += 1;
        }
        const bytes = try estimate(raw, request);
        self.mutex.lock();
        if (bytes > self.compact_cap - @min(self.compact_cap, self.compact_bytes)) {
            self.mutex.unlock();
            return error.CpuReplayCompactBudget;
        }
        self.compact_bytes += bytes;
        self.mutex.unlock();
        errdefer self.releaseBudget(bytes);
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .backend = self, .capture = try Interface.Capture.init(a, request.native), .request = request, .charged_bytes = bytes };
        return .{ .context = owner, .retained_host_bytes = bytes, .park = Owner.park, .restore = Owner.restore, .release = Owner.release };
    }
    fn releaseRetained(self: *Context) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.retained_live > 0);
        self.retained_live -= 1;
    }
    fn releaseBudget(self: *Context, bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.compact_bytes >= bytes);
        self.compact_bytes -= bytes;
    }
};
/// Resident worker: MAIN, binding and compact facts stay where stage one left
/// them (the non-replay path); nothing is copied, discarded or regenerated.
const Retained = struct {
    allocator: std.mem.Allocator,
    backend: *Context,
    ordinal: u32,
    phase: enum { captured, parked, restored } = .captured,
    fn park(raw: *anyopaque, worker: *Worker) !void {
        const self: *Retained = @ptrCast(@alignCast(raw));
        if (self.phase != .captured or !worker.sealed or worker.consumed) return error.CpuReplayPhase;
        const scope = worker.scheme.device_om31_scope orelse return error.CpuReplayScope;
        if (scope.ordinal != self.ordinal) return error.CpuReplayScope;
        self.phase = .parked;
        std.debug.print("GPU_CPU_REPLAY_RETAIN ordinal={} compact_host_bytes=0 main_resident=true\n", .{self.ordinal});
    }
    fn restore(raw: *anyopaque, worker: *Worker) !void {
        const self: *Retained = @ptrCast(@alignCast(raw));
        if (self.phase != .parked) return error.CpuReplayPhase;
        const scope = worker.scheme.device_om31_scope orelse return error.CpuReplayScope;
        if (scope.ordinal != self.ordinal) return error.CpuReplayScope;
        self.phase = .restored;
    }
    fn release(raw: *anyopaque) void {
        const self: *Retained = @ptrCast(@alignCast(raw));
        self.backend.releaseRetained();
        self.allocator.destroy(self);
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    backend: *Context,
    capture: Interface.Capture,
    request: Request,
    charged_bytes: usize,
    phase: enum { captured, parking, parked, restoring, restored } = .captured,
    scope: ?D.Scope = null,
    fn park(raw: *anyopaque, worker: *Worker) !void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.phase != .captured or !worker.sealed or worker.consumed or !worker.source.device_generated or !worker.local_metadata_retired) return error.CpuReplayPhase;
        const scope = worker.scheme.device_om31_scope orelse return error.CpuReplayScope;
        if (scope.ordinal != self.request.scope.ordinal or !std.mem.eql(u8, &scope.statement, &self.request.scope.statement) or !std.mem.eql(u8, &scope.fixed, &self.request.scope.fixed)) return error.CpuReplayScope;
        self.phase = .parking;
        self.scope = scope;
        const child = worker.child orelse return error.CpuReplayPhase;
        try child.parkDeviceBinding();
        try self.backend.service.discardRetainedMain(scope);
        self.phase = .parked;
        std.debug.print("GPU_CPU_REPLAY_PARK ordinal={} compact_host_bytes={} binding_device_bytes={}\n", .{ scope.ordinal, self.charged_bytes, worker.child.?.device_binding.?.retained_bytes });
    }
    fn restore(raw: *anyopaque, worker: *Worker) !void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.phase != .parked) return error.CpuReplayPhase;
        const scope = self.scope orelse return error.CpuReplayScope;
        const actual_scope = worker.scheme.device_om31_scope orelse return error.CpuReplayScope;
        if (!std.meta.eql(scope, actual_scope)) return error.CpuReplayScope;
        self.phase = .restoring;
        var request = self.request;
        request.native = &self.capture.value;
        const stage = self.backend.source.stage();
        var source = try stage.invoke(self.allocator, request);
        var transferred = false;
        errdefer if (!transferred) source.deinit();
        const columns = try source.mainTraceColumns(self.allocator, worker.setup);
        defer self.allocator.free(columns);
        const commit = self.backend.trace.stage();
        const main = try commit.commit(commit.context, self.allocator, .{ .scope = request.scope, .tree_index = 1, .config = worker.config, .columns = columns, .expected_main_root = scope.main });
        try worker.scheme.refreshDeviceOm31Main(main);
        try source.releaseMain();
        var old_source = worker.source;
        worker.source = source;
        transferred = true;
        defer old_source.deinit();
        worker.local_metadata_retired = false;
        const fixed = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
        const fixed_columns = try self.allocator.alloc(D.Column, fixed.len);
        defer self.allocator.free(fixed_columns);
        for (fixed, fixed_columns) |coefficient, *column| column.* = .{ .log_size = coefficient.logSize(), .coefficients = coefficient.coefficients() };
        try worker.child.?.replayDeviceBinding(self.allocator, worker.gkr_budget, worker.numerical_gkr_stage orelse return error.DeviceBindingReplayUnavailable, worker.instances, CPU.rv64_gkr_native_provider.Provider{ .source = &worker.source }, Child.NativeColumns{ .fixed = fixed_columns, .main = main.columns });
        try worker.retireLocalMetadata();
        self.phase = .restored;
        self.backend.releaseBudget(self.charged_bytes);
        self.charged_bytes = 0;
        std.debug.print("GPU_CPU_REPLAY_RESTORED ordinal={} main_root_match=true projection_digest_match=true\n", .{scope.ordinal});
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.capture.deinit();
        self.backend.releaseBudget(self.charged_bytes);
        self.allocator.destroy(self);
    }
};
