const benchmark = @import("../bench/main.zig");
const MetalProverEngine =
    @import("../../../integrations/riscv_metal/mod.zig").MetalProverEngine;

pub fn main() !void {
    return benchmark.mainWithEngine(MetalProverEngine);
}
