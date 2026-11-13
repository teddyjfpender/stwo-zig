//! Explicit CUDA outer recursion from original trace-only graphs and compact
//! proof seeds. Missing generation capabilities and device refusals are terminal.
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const Native = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native;
const Trace = @import("stwo_riscv_cuda_integration").rv64.trace_commit;
const Composition = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const Source = @import("stwo_riscv_cuda_integration").rv64.outer_source;
pub fn main() !void {
    const a = std.heap.page_allocator;
    if (std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICES")) return error.MultiGpuOuterRecursionNotImplemented;
    const library = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_LIBRARY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.GpuOuterRequiresNativeLibrary,
        else => return err,
    };
    defer a.free(library);
    const device_text = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_DEVICE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (device_text) |text| a.free(text);
    const device: u32 = if (device_text) |text| std.fmt.parseUnsigned(u32, text, 10) catch return error.InvalidGpuDevice else 0;
    const cap_text = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_BYTE_CAP") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (cap_text) |text| a.free(text);
    const cap: usize = if (cap_text) |text| std.fmt.parseUnsigned(usize, text, 10) catch return error.InvalidGpuByteCap else 28 << 30;
    if (cap == 0) return error.InvalidGpuByteCap;
    var native = try Native.Context.init(library, device, cap);
    defer native.deinit();
    var trace = try Trace.Context.init(&native);
    defer trace.deinit();
    var composition = try Composition.Context.initNumerical(a, &native);
    defer composition.deinit();
    var source = try Source.Context.init(a, &native, &trace, &composition);
    defer source.deinit();
    const factory = try source.factoryForTraceOnly();
    std.log.info("CUDA outer requested: device={d} byte_cap={d}; GPU assignments from original circuit graph; host graph/setup; no CPU proving fallback", .{ device, cap });
    try ProductCPU.rv64_ethereum_gkr_main.mainWithRecursionFactory(factory);
}
