//! Same Ethereum producer/receiver, with explicit experimental GPU PCS offload.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Native = @import("rv64/pcs_native.zig");
const Gkr = @import("rv64/gkr_stage.zig");
const TraceCommit = @import("rv64/trace_commit.zig");
const CpuProjection = @import("rv64/cpu_projection.zig");
const ResidentComposition = @import("rv64/resident_composition.zig");
const H = @import("rv64/hybrid_pcs.zig");
const Composition = @import("rv64/real_composition.zig");
pub fn main() !void {
    const a = std.heap.page_allocator;
    const native_library = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_LIBRARY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (native_library) |path| a.free(path);
    const arguments = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, arguments);
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "resident-batch")) {
        if (arguments.len != 4) return error.ExpectedResidentBatchManifestAndOutput;
        return @import("rv64/resident_batch.zig").run(a, native_library orelse return error.ResidentBatchRequiresNativeLibrary, arguments[2], arguments[3]);
    }
    const host_retained = std.process.hasEnvVarConstant("STWO_RV64_GPU_HOST_RETAINED");
    try @import("rv64/host_retained_policy.zig").validate(host_retained, native_library != null, std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES"), std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE"), std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING"));
    if (native_library) |path| {
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES")) {
            if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) return error.ResidentPoolRequiresDeviceTrace;
            if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) return error.FullyResidentBindingRequired;
            const planned_text = try std.process.getEnvVarOwned(a, "STWO_RV64_GPU_PLANNED_CPU_WORKERS");
            defer a.free(planned_text);
            const planned = std.fmt.parseInt(usize, planned_text, 10) catch return error.InvalidResidentPlan;
            var config = try @import("rv64/resident_router.zig").Config.fromEnv(a);
            defer config.deinit(a);
            const pool = try @import("rv64/resident_pool.zig").Pool.createWithBinding(a, path, config, planned, std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING"));
            defer pool.deinit();
            std.debug.print("GPU_RESIDENT_PLAN devices={d} planned_cpu_workers={d} retained_scopes_per_device={d} host_budget=resource_file gpu_caps_bytes={any}\n", .{ config.ids.len, planned, config.scope_limit, config.caps });
            try CPU.rv64_ethereum_gkr_main.mainWithResidentPipeline(pool.stages());
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
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) {
            if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) return error.DeviceBindingRequiresResidentTraceCommit;
            try gkr.enableDeviceBinding(&native.library);
        }
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) gkr.fixed_provider = .{ .context = &native, .acquire = Native.Context.provideFixed, .release = Native.Context.releaseProvidedFixed };
        const gkr_stage = gkr.stage();
        var composition = try ResidentComposition.Context.init(a, &native);
        defer composition.deinit();
        const resident_composition_stage = composition.stage();
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) {
            if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) return error.FullyResidentBindingRequired;
            var trace = try TraceCommit.Context.init(&native);
            defer trace.deinit();
            const trace_stage = trace.stage();
            var global_interaction = try @import("rv64/global_stage.zig").Context.init(&native);
            defer global_interaction.deinit();
            var projection = try CpuProjection.Context.init(&native);
            defer projection.deinit();
            var core_source = try @import("rv64/core_witness.zig").Context.init(&native, &projection);
            var bridge = try @import("rv64/bridge_witness.zig").Context.init(&native);
            var bulk_sponge = try @import("rv64/bulk_sponge.zig").Context.init(&native);
            const contributors = [_]@import("rv64/device_source.zig").Contributor{ bridge.contributor(), bulk_sponge.contributor() };
            var source = @import("rv64/device_source.zig").Context{ .core = &core_source, .contributors = &contributors };
            var truth_source = try @import("rv64/truth_source.zig").Context.init(a, &native, &trace, &global_interaction);
            defer truth_source.deinit();
            const truth_composition = try composition.truthStage();
            try CPU.rv64_ethereum_gkr_main.mainWithResidentPipeline(.{ .source = source.stage(), .truth_source = truth_source.stage(), .truth_composition = truth_composition, .truth_pcs = &native_stage, .pcs = &native_stage, .numerical = &gkr_stage, .resident_composition = &resident_composition_stage, .trace_commit = &trace_stage, .global_interaction = global_interaction.stage(), .cpu_projection = projection.stage() });
        } else try CPU.rv64_ethereum_gkr_main.mainWithResidentStages(&native_stage, null, &gkr_stage, &resident_composition_stage);
        return;
    }
    const helper = try std.process.getEnvVarOwned(a, "STWO_RV64_GPU_PCS_HELPER");
    defer a.free(helper);
    const directory = try std.process.getEnvVarOwned(a, "STWO_RV64_GPU_WORKDIR");
    defer a.free(directory);
    try std.fs.cwd().makePath(directory);
    var context = H.Context{ .helper = helper, .directory = directory };
    const stage = context.stage();
    const composition_helper = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_COMPOSITION_HELPER") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (composition_helper) |value| a.free(value);
    var composition = Composition.Context{ .helper = composition_helper orelse "", .directory = directory, .keep_jobs = std.process.hasEnvVarConstant("STWO_RV64_GPU_KEEP_JOBS") };
    const composition_stage = composition.stage();
    try CPU.rv64_ethereum_gkr_main.mainWithStages(&stage, if (composition_helper != null) &composition_stage else null);
}
