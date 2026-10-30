const std = @import("std");
const Plan = @import("integrations/riscv_cuda/resident_parent_composite_plan_v1.zig");
test "resident composite cold schedule codegen" {
    std.mem.doNotOptimizeAway(&Plan.Plan.initFull);
}

const Runtime = @import("integrations/riscv_cuda/resident_parent_composite_v1.zig");
const Prover = @import("integrations/riscv_cuda/resident_parent_prover_v1.zig");
test "resident composite device schedule codegen" {
    std.mem.doNotOptimizeAway(&Prover.For(Runtime.Plan).prove);
}

comptime {
    _ = Plan;
    _ = @import("integrations/riscv_cuda/resident_parent_arithmetic_v1.zig");
}
