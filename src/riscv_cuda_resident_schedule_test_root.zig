const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_schedule_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_schedule_seeds_v1.zig"));
}
