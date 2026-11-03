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
    source: CPU.rv64_device_source_stage,
    truth_source: CPU.rv64_gkr_truth_device_source.Stage,
    truth_composition: CPU.rv64_gkr_truth_device_composition.Stage,
    global_interaction: Worker.DeviceGlobal.Stage,
    const Device = struct {
        native: @import("pcs_native.zig").Context,
        global_interaction: @import("global_stage.zig").Context,
        gkr: @import("gkr_stage.zig").Backend,
        composition: @import("resident_composition.zig").Context,
        trace: @import("trace_commit.zig").Context,
        projection: @import("cpu_projection.zig").Context,
        core_source: @import("core_witness.zig").Context,
        bridge: @import("bridge_witness.zig").Context,
        bulk_sponge: @import("bulk_sponge.zig").Context,
        contributors: [2]@import("device_source.zig").Contributor,
        source: @import("device_source.zig").Context,
        cpu_replay: @import("cpu_replay.zig").Context,
        truth_source: @import("truth_source.zig").Context,
        truth_composition: CPU.rv64_gkr_truth_device_composition.Stage,
        fn init(self: *Device, a: std.mem.Allocator, library: []const u8, id: u32, cap: u64, device_binding: bool) !void {
            self.native = try @import("pcs_native.zig").Context.init(library, id, cap);
            errdefer self.native.deinit();
            self.gkr = try @import("gkr_stage.zig").Backend.init(a, &self.native.library, self.native.session, std.math.cast(usize, cap) orelse return error.InvalidResidentDeviceCaps);
            errdefer self.gkr.deinit();
            if (device_binding) try self.gkr.enableDeviceBinding(&self.native.library);
            self.gkr.fixed_provider = .{ .context = &self.native, .acquire = @import("pcs_native.zig").Context.provideFixed, .release = @import("pcs_native.zig").Context.releaseProvidedFixed };
            self.gkr.coefficient_sink = .{ .context = &self.native, .publish = @import("pcs_native.zig").Context.publishCoefficients };
            self.composition = try @import("resident_composition.zig").Context.init(a, &self.native);
            errdefer self.composition.deinit();
            self.trace = try @import("trace_commit.zig").Context.init(&self.native);
            errdefer self.trace.deinit();
            self.projection = try @import("cpu_projection.zig").Context.init(&self.native);
            errdefer self.projection.deinit();
            self.global_interaction = try @import("global_stage.zig").Context.init(&self.native);
            errdefer self.global_interaction.deinit();
            self.core_source = try @import("core_witness.zig").Context.init(&self.native, &self.projection);
            self.bridge = try @import("bridge_witness.zig").Context.init(&self.native);
            self.bulk_sponge = try @import("bulk_sponge.zig").Context.init(&self.native);
            self.contributors = .{ self.bridge.contributor(), self.bulk_sponge.contributor() };
            self.source = .{ .core = &self.core_source, .contributors = &self.contributors };
            self.truth_source = try @import("truth_source.zig").Context.init(a, &self.native, &self.trace, &self.global_interaction);
            errdefer self.truth_source.deinit();
            self.truth_composition = try self.composition.truthStage();
        }
        fn deinit(self: *Device) void {
            self.cpu_replay.deinit();
            self.truth_source.deinit();
            self.global_interaction.deinit();
            self.projection.deinit();
            self.trace.deinit();
            self.composition.deinit();
            self.gkr.deinit();
            self.native.deinit();
        }
    };
    pub fn create(a: std.mem.Allocator, library: []const u8, config: Config, cpu_workers: usize) !*Pool {
        return createWithBinding(a, library, config, cpu_workers, false);
    }
    pub fn createWithBinding(a: std.mem.Allocator, library: []const u8, config: Config, cpu_workers: usize, device_binding: bool) !*Pool {
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_CPU_REPLAY") and !device_binding) return error.CpuReplayRequiresDeviceBinding;
        try config.validatePlan(cpu_workers);
        const self = try a.create(Pool);
        errdefer a.destroy(self);
        self.allocator = a;
        self.devices = try a.alloc(Device, config.ids.len);
        errdefer a.free(self.devices);
        var initialized: usize = 0;
        errdefer for (self.devices[0..initialized]) |*device| device.deinit();
        for (self.devices, config.ids, config.caps) |*device, id, cap| {
            try device.init(a, library, id, cap, device_binding);
            initialized += 1;
            device.cpu_replay = .{ .service = &device.native, .source = &device.source, .trace = &device.trace };
            try device.native.configureRetention(config.scope_limit);
        }
        self.endpoints = try a.alloc(Endpoint, config.ids.len);
        errdefer a.free(self.endpoints);
        for (self.endpoints, self.devices, config.ids, config.caps) |*endpoint, *device, id, cap| endpoint.* = .{ .cpu_replay = device.cpu_replay.stage(), .device = id, .byte_cap = cap, .pcs = device.native.stage(), .numerical = device.gkr.stage(), .composition = device.composition.stage(), .trace_commit = device.trace.stage(), .projection = device.projection.stage(), .global_interaction = device.global_interaction.stage(), .source = device.source.stage(), .truth_source = device.truth_source.stage(), .truth_composition = device.truth_composition };
        self.router = try Router.initWithCapacity(self.endpoints, cpu_workers, config.scope_limit);
        self.pcs = self.router.pcsStage();
        self.truth_pcs = self.router.truthPcsStage();
        self.numerical = self.router.numericalStage();
        self.composition = self.router.compositionStage();
        self.trace_commit = self.router.traceStage();
        self.projection = self.router.projectionStage();
        self.source = self.router.sourceStage();
        self.truth_source = self.router.truthSourceStage();
        self.truth_composition = self.router.truthCompositionStage();
        self.global_interaction = self.router.globalStage();
        return self;
    }
    pub fn stages(self: *Pool) CPU.rv64_ethereum_gkr_main.ResidentStages {
        var result = CPU.rv64_ethereum_gkr_main.ResidentStages{ .source = self.source, .truth_source = self.truth_source, .truth_composition = self.truth_composition, .global_interaction = self.global_interaction, .pcs = &self.pcs, .numerical = &self.numerical, .resident_composition = &self.composition, .trace_commit = &self.trace_commit, .cpu_projection = self.projection };
        if (comptime @hasField(CPU.rv64_ethereum_gkr_main.ResidentStages, "truth_pcs")) result.truth_pcs = &self.truth_pcs;
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_CPU_REPLAY")) result.cpu_replay = self.router.cpuReplayStage();
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
