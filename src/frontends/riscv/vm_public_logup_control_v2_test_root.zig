const std = @import("std");

test "VM public-LogUp V2 focused inventory compiles" {
    std.testing.refAllDeclsRecursive(
        @import("recursion/air/vm_public_logup_control_v2_test.zig"),
    );
}
