//! Bounded GPU MAIN/P8 replay across the shared-challenge manifest barrier.
//! Retains compact capture only; original MAIN root and authenticated P8 digest
//! are checked before the replayed columns can enter the physical proof.
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
    mutex: std.Thread.Mutex = .{},
    pub fn deinit(self: *Context) void {
        std.debug.assert(self.compact_bytes == 0);
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
    fn releaseBudget(self: *Context, bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.compact_bytes >= bytes);
        self.compact_bytes -= bytes;
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
