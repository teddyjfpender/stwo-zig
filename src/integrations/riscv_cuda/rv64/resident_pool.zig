//! Concrete per-device RV64 native sessions and their resident stage backends.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const D = CPU.rv64_device_pcs;
const Child = CPU.rv64_gkr_child;
const Worker = CPU.rv64_gkr_cpu_worker;
const Source = CPU.rv64_cpu_source;
const R = @import("resident_router.zig");
const Router = R.Router;
const Config = R.Config;
const Endpoint = R.Endpoint;
/// Owns the actual native CUDA sessions and the concrete RV64 backends. Creation
/// performs capacity planning before opening any device; no GPU is rented here.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    devices: []Device,
    endpoints: []Endpoint,
    router: Router,
    pcs: D.Stage,
    truth_pcs: D.Stage,
    numerical: Child.NumericalStage,
    composition: Worker.ResidentCompositionStage,
    trace_commit: D.TraceCommitStage,
    projection: Source.ProjectionStage,
    const Device = struct {
        native: @import("pcs_native.zig").Context,
        gkr: @import("gkr_stage.zig").Backend,
        composition: @import("resident_composition.zig").Context,
        trace: @import("trace_commit.zig").Context,
        projection: @import("cpu_projection.zig").Context,
        fn init(self: *Device, a: std.mem.Allocator, library: []const u8, id: u32, cap: u64) !void {
            self.native = try @import("pcs_native.zig").Context.init(library, id, cap);
            errdefer self.native.deinit();
            self.gkr = try @import("gkr_stage.zig").Backend.init(a, &self.native.library, self.native.session, std.math.cast(usize, cap) orelse return error.InvalidResidentDeviceCaps);
            errdefer self.gkr.deinit();
            self.gkr.coefficient_sink = .{ .context = &self.native, .publish = @import("pcs_native.zig").Context.publishCoefficients };
            self.composition = try @import("resident_composition.zig").Context.init(a, &self.native);
            errdefer self.composition.deinit();
            self.trace = try @import("trace_commit.zig").Context.init(&self.native);
            errdefer self.trace.deinit();
            self.projection = try @import("cpu_projection.zig").Context.init(&self.native);
        }
        fn deinit(self: *Device) void {
            self.projection.deinit();
            self.trace.deinit();
            self.composition.deinit();
            self.gkr.deinit();
            self.native.deinit();
        }
    };
    pub fn create(a: std.mem.Allocator, library: []const u8, config: Config, cpu_workers: usize) !*Pool {
        try config.validatePlan(cpu_workers);
        const self = try a.create(Pool);
        errdefer a.destroy(self);
        self.allocator = a;
        self.devices = try a.alloc(Device, config.ids.len);
        errdefer a.free(self.devices);
        var initialized: usize = 0;
        errdefer for (self.devices[0..initialized]) |*device| device.deinit();
        for (self.devices, config.ids, config.caps) |*device, id, cap| {
            try device.init(a, library, id, cap);
            initialized += 1;
        }
        self.endpoints = try a.alloc(Endpoint, config.ids.len);
        errdefer a.free(self.endpoints);
        for (self.endpoints, self.devices, config.ids, config.caps) |*endpoint, *device, id, cap| endpoint.* = .{ .device = id, .byte_cap = cap, .pcs = device.native.stage(), .numerical = device.gkr.stage(), .composition = device.composition.stage(), .trace_commit = device.trace.stage(), .projection = device.projection.stage() };
        self.router = try Router.init(self.endpoints, cpu_workers);
        self.pcs = self.router.pcsStage();
        self.truth_pcs = self.router.truthPcsStage();
        self.numerical = self.router.numericalStage();
        self.composition = self.router.compositionStage();
        self.trace_commit = self.router.traceStage();
        self.projection = self.router.projectionStage();
        return self;
    }
    pub fn stages(self: *Pool) CPU.rv64_ethereum_gkr_main.ResidentStages {
        var result = CPU.rv64_ethereum_gkr_main.ResidentStages{ .pcs = &self.pcs, .numerical = &self.numerical, .resident_composition = &self.composition, .trace_commit = &self.trace_commit, .cpu_projection = self.projection };
        if (comptime @hasField(CPU.rv64_ethereum_gkr_main.ResidentStages, "truth_pcs")) result.truth_pcs = &self.truth_pcs;
        return result;
    }
    pub fn deinit(self: *Pool) void {
        const a = self.allocator;
        for (self.devices) |*device| device.deinit();
        a.free(self.devices);
        a.free(self.endpoints);
        a.destroy(self);
    }
};
