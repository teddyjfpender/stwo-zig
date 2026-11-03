//! Same Ethereum producer/receiver, with explicit experimental GPU PCS offload.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const H = @import("rv64/hybrid_pcs.zig");
const Composition = @import("rv64/real_composition.zig");
pub fn main() !void {
    const a = std.heap.page_allocator;
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
