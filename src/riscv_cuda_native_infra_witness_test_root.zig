const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_infra_witness_v1.zig"));
}
