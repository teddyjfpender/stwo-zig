const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_counter_wide_v1.zig"));
}
