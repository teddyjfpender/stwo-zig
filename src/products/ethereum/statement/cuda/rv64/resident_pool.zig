//! Concrete per-device RV64 native sessions and their resident stage backends.
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const D = CPU.rv64_device_pcs;
const Child = CPU.rv64_gkr_child;
const Worker = CPU.rv64_gkr_cpu_worker;
const Source = CPU.rv64_cpu_source;
const R = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.resident_router;
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
        native: @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Context,
        global_interaction: @import("stwo_riscv_cuda_integration").rv64.execution.source.global_stage.Context,
        gkr: @import("stwo_riscv_cuda_integration").rv64.gkr_stage.Backend,
        composition: @import("stwo_riscv_cuda_integration").rv64.resident_composition.Context,
        trace: @import("stwo_riscv_cuda_integration").rv64.trace_commit.Context,
        projection: @import("stwo_riscv_cuda_integration").rv64.cpu_projection.Context,
        core_source: @import("stwo_riscv_cuda_integration").rv64.core_witness.Context,
        bridge: @import("stwo_riscv_cuda_integration").rv64.bridge_witness.Context,
        bulk_sponge: @import("stwo_riscv_cuda_integration").rv64.execution.source.bulk_sponge.Context,
        contributors: [2]@import("stwo_riscv_cuda_integration").rv64.device_source.Contributor,
        source: @import("stwo_riscv_cuda_integration").rv64.device_source.Context,
        cpu_replay: @import("stwo_riscv_cuda_integration").rv64.execution.source.cpu_replay.Context,
        truth_source: @import("stwo_riscv_cuda_integration").rv64.truth_source.Context,
        truth_composition: CPU.rv64_gkr_truth_device_composition.Stage,
        fn init(self: *Device, a: std.mem.Allocator, library: []const u8, id: u32, cap: u64, device_binding: bool) !void {
            self.native = try @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Context.init(library, id, cap);
            errdefer self.native.deinit();
            self.gkr = try @import("stwo_riscv_cuda_integration").rv64.gkr_stage.Backend.init(a, &self.native.library, self.native.session, std.math.cast(usize, cap) orelse return error.InvalidResidentDeviceCaps);
            errdefer self.gkr.deinit();
            self.gkr.service = &self.native;
            if (device_binding) try self.gkr.enableDeviceBinding(&self.native.library);
            self.gkr.fixed_provider = .{ .context = &self.native, .acquire = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Context.provideFixed, .release = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Context.releaseProvidedFixed };
            self.gkr.coefficient_sink = .{ .context = &self.native, .publish = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native.Context.publishCoefficients };
            self.composition = try @import("stwo_riscv_cuda_integration").rv64.resident_composition.Context.init(a, &self.native);
            errdefer self.composition.deinit();
            self.trace = try @import("stwo_riscv_cuda_integration").rv64.trace_commit.Context.init(&self.native);
            errdefer self.trace.deinit();
            self.projection = try @import("stwo_riscv_cuda_integration").rv64.cpu_projection.Context.init(&self.native);
            errdefer self.projection.deinit();
            if (self.trace.freeze_allocation_plan) {
                // Pool allocator lives through warm requests and cache teardown.
                self.trace.host_allocator = a;
                self.projection.host_allocator = a;
            }
            self.global_interaction = try @import("stwo_riscv_cuda_integration").rv64.execution.source.global_stage.Context.init(&self.native);
            errdefer self.global_interaction.deinit();
            self.core_source = try @import("stwo_riscv_cuda_integration").rv64.core_witness.Context.init(&self.native, &self.projection);
            self.bridge = try @import("stwo_riscv_cuda_integration").rv64.bridge_witness.Context.init(&self.native);
            self.bulk_sponge = try @import("stwo_riscv_cuda_integration").rv64.execution.source.bulk_sponge.Context.init(&self.native);
            self.contributors = .{ self.bridge.contributor(), self.bulk_sponge.contributor() };
            self.source = .{ .core = &self.core_source, .contributors = &self.contributors };
            self.truth_source = try @import("stwo_riscv_cuda_integration").rv64.truth_source.Context.init(a, &self.native, &self.trace, &self.global_interaction);
            errdefer self.truth_source.deinit();
            self.truth_source.composition = &self.composition;
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
    pub fn stages(self: *Pool) ProductCPU.rv64_ethereum_gkr_main.ResidentStages {
        var result = ProductCPU.rv64_ethereum_gkr_main.ResidentStages{ .source = self.source, .truth_source = self.truth_source, .truth_composition = self.truth_composition, .global_interaction = self.global_interaction, .pcs = &self.pcs, .numerical = &self.numerical, .resident_composition = &self.composition, .trace_commit = &self.trace_commit, .cpu_projection = self.projection };
        if (comptime @hasField(ProductCPU.rv64_ethereum_gkr_main.ResidentStages, "truth_pcs")) result.truth_pcs = &self.truth_pcs;
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
