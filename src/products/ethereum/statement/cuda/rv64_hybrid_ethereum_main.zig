//! Same Ethereum producer/receiver, with explicit experimental GPU PCS offload.
const std = @import("std");
const CPU = @import("ethereum_cpu_component");
const Capture = @import("rv64/capture_execution.zig");
const Native = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native;
const Gkr = @import("stwo_riscv_cuda_integration").rv64.gkr_stage;
const TraceCommit = @import("stwo_riscv_cuda_integration").rv64.trace_commit;
const CpuProjection = @import("stwo_riscv_cuda_integration").rv64.cpu_projection;
const ResidentComposition = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const H = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.hybrid_pcs;
const Composition = @import("stwo_riscv_cuda_integration").rv64.execution.composition.real_composition;
pub fn main() !void {
    const a = std.heap.page_allocator;
    const native_library = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_LIBRARY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (native_library) |path| a.free(path);
    const arguments = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, arguments);
    var capture = Capture.Session{};
    defer capture.deinit();
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "resident-batch")) {
        if (arguments.len != 4) return error.ExpectedResidentBatchManifestAndOutput;
        return @import("rv64/resident_batch.zig").run(a, native_library orelse return error.ResidentBatchRequiresNativeLibrary, arguments[2], arguments[3]);
    }
    const host_retained = std.process.hasEnvVarConstant("STWO_RV64_GPU_HOST_RETAINED");
    const device_trace = std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE");
    try @import("rv64/host_retained_policy.zig").validate(host_retained, native_library != null, std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES"), device_trace, device_trace);
    if (std.process.hasEnvVarConstant("STWO_RV64_GPU_CPU_REPLAY") and (host_retained or native_library == null or !std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES") or !device_trace)) return error.CpuReplayRequiresFullyResidentPool;
    if (native_library) |path| {
        capture = Capture.Session.args(a, arguments);
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES")) {
            if (!device_trace) return error.ResidentPoolRequiresDeviceTrace;
            const planned_text = try std.process.getEnvVarOwned(a, "STWO_RV64_GPU_PLANNED_CPU_WORKERS");
            defer a.free(planned_text);
            const planned = std.fmt.parseInt(usize, planned_text, 10) catch return error.InvalidResidentPlan;
            var config = try @import("stwo_riscv_cuda_integration").rv64.execution.runtime.resident_router.Config.fromEnv(a);
            defer config.deinit(a);
            const pool = try @import("rv64/resident_pool.zig").Pool.createWithBinding(a, path, config, planned, true);
            defer pool.deinit();
            for (pool.devices) |*device| capture.attach(&device.native.recording);
            std.debug.print("GPU_RESIDENT_PLAN devices={d} planned_cpu_workers={d} retained_scopes_per_device={d} host_budget=resource_file gpu_caps_bytes={any}\n", .{ config.ids.len, planned, config.scope_limit, config.caps });
            try CPU.rv64_ethereum_gkr_main.mainWithResidentPipeline(pool.stages());
            capture.success = true;
            return;
        }
        const cap_text = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_BYTE_CAP") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (cap_text) |text| a.free(text);
        const cap: usize = if (cap_text) |text| std.fmt.parseInt(usize, text, 10) catch return error.InvalidGpuByteCap else 24 * 1024 * 1024 * 1024;
        if (cap == 0) return error.InvalidGpuByteCap;
        var native = try Native.Context.init(path, 0, cap);
        defer native.deinit();
        capture.attach(&native.recording);
        const scope_text = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_RETAINED_SCOPES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (scope_text) |text| a.free(text);
        if (scope_text) |text| try native.configureRetention(std.fmt.parseInt(usize, text, 10) catch return error.InvalidRetainedScopeLimit);
        const native_stage = native.stage();
        var gkr = try Gkr.Backend.init(a, &native.library, native.session, cap);
        defer gkr.deinit();
        // The explicit hybrid control keeps MAIN in the bounded host spill store.
        // GKR ingress is temporary: never publish device MAIN across the barrier.
        if (!host_retained) gkr.coefficient_sink = .{ .context = &native, .publish = Native.Context.publishCoefficients };
        if (host_retained) std.debug.print("GPU_EXECUTION_MODE host_retained_hybrid stage1_device_main_retention=0 stage2=resident_composition_pcs\n", .{});
        if (device_trace) {
            try gkr.enableDeviceBinding(&native.library);
        }
        if (device_trace) gkr.fixed_provider = .{ .context = &native, .acquire = Native.Context.provideFixed, .release = Native.Context.releaseProvidedFixed };
        const gkr_stage = gkr.stage();
        try @import("rv64/host_retained_policy.zig").requireBinding(device_trace, gkr_stage.bind != null);
        var composition = try ResidentComposition.Context.init(a, &native);
        defer composition.deinit();
        const resident_composition_stage = composition.stage();
        if (device_trace) {
            var trace = try TraceCommit.Context.init(&native);
            defer trace.deinit();
            const trace_stage = trace.stage();
            var global_interaction = try @import("stwo_riscv_cuda_integration").rv64.execution.source.global_stage.Context.init(&native);
            defer global_interaction.deinit();
            var projection = try CpuProjection.Context.init(&native);
            defer projection.deinit();
            var core_source = try @import("stwo_riscv_cuda_integration").rv64.core_witness.Context.init(&native, &projection);
            var bridge = try @import("stwo_riscv_cuda_integration").rv64.bridge_witness.Context.init(&native);
            var bulk_sponge = try @import("stwo_riscv_cuda_integration").rv64.execution.source.bulk_sponge.Context.init(&native);
            const contributors = [_]@import("stwo_riscv_cuda_integration").rv64.device_source.Contributor{ bridge.contributor(), bulk_sponge.contributor() };
            var source = @import("stwo_riscv_cuda_integration").rv64.device_source.Context{ .core = &core_source, .contributors = &contributors };
            var truth_source = try @import("stwo_riscv_cuda_integration").rv64.truth_source.Context.init(a, &native, &trace, &global_interaction);
            defer truth_source.deinit();
            const truth_composition = try composition.truthStage();
            try CPU.rv64_ethereum_gkr_main.mainWithResidentPipeline(.{ .source = source.stage(), .truth_source = truth_source.stage(), .truth_composition = truth_composition, .truth_pcs = &native_stage, .pcs = &native_stage, .numerical = &gkr_stage, .resident_composition = &resident_composition_stage, .trace_commit = &trace_stage, .global_interaction = global_interaction.stage(), .cpu_projection = projection.stage() });
        } else try CPU.rv64_ethereum_gkr_main.mainWithResidentStages(&native_stage, null, &gkr_stage, &resident_composition_stage);
        capture.success = true;
        return;
    }
    const helper = try std.process.getEnvVarOwned(a, "STWO_RV64_GPU_PCS_HELPER");
    defer a.free(helper);
    const scratch = try @import("rv64/hybrid_scratch_output.zig").directory(a, arguments);
    defer if (scratch) |value| a.free(value);
    const directory = scratch orelse "";
    var context = H.Context{ .helper = helper, .directory = directory };
    const stage = context.stage();
    const composition_helper = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_COMPOSITION_HELPER") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (composition_helper) |value| a.free(value);
    var composition = Composition.Context{ .helper = composition_helper orelse "", .directory = directory, .keep_jobs = false };
    const composition_stage = composition.stage();
    try CPU.rv64_ethereum_gkr_main.mainWithStages(&stage, if (composition_helper != null) &composition_stage else null);
    capture.success = true;
}
