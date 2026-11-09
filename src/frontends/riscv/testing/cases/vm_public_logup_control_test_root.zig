const std = @import("std");

test "VM public-LogUp V2 focused inventory compiles" {
    std.testing.refAllDeclsRecursive(
        @import("stwo_riscv_recursion_air").modules.tests_vm_public_logup_control_test,
    );
}
