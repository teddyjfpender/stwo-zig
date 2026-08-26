const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

pub const Engine = frontend.prover_mod.ProverEngineForBackend(
    @import("stwo_cpu_backend").CpuBackend,
);

pub fn initialize(_: std.mem.Allocator) !void {}
pub fn shutdown() void {}
