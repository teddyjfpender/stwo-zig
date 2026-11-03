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
    if (native_library) |path| {
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
        gkr.coefficient_sink = .{ .context = &native, .publish = Native.Context.publishCoefficients };
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) {
            if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) return error.DeviceBindingRequiresResidentTraceCommit;
            try gkr.enableDeviceBinding(&native.library);
        }
        const gkr_stage = gkr.stage();
        var composition = try ResidentComposition.Context.init(a, &native);
        defer composition.deinit();
        const resident_composition_stage = composition.stage();
        if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE")) {
            var trace = try TraceCommit.Context.init(&native);
            defer trace.deinit();
            const trace_stage = trace.stage();
            var projection = try CpuProjection.Context.init(&native);
            defer projection.deinit();
            try CPU.rv64_ethereum_gkr_main.mainWithResidentPipeline(.{ .pcs = &native_stage, .numerical = &gkr_stage, .resident_composition = &resident_composition_stage, .trace_commit = &trace_stage, .cpu_projection = projection.stage() });
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
