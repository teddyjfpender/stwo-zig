const benchmark = @import("../bench/runner.zig");
const frontend = @import("stwo_riscv_frontend");
const MetalProverEngine =
    @import("stwo_riscv_metal_integration").MetalProverEngine;

pub fn main() !void {
    return benchmark.mainWithEngine(frontend, MetalProverEngine, .metal);
}
