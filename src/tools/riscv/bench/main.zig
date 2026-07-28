//! CPU entry point for the shared RISC-V proof benchmark command.

const benchmark = @import("runner.zig");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("../../../integrations/riscv_cpu/mod.zig");

pub fn main() !void {
    return benchmark.mainWithEngine(frontend, riscv_cpu.CpuProverEngine);
}
