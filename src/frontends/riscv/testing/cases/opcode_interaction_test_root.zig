const std = @import("std");

test {
    _ = @import("stwo_riscv_rv32");
    std.testing.refAllDecls(@This());
}
