const std = @import("std");
const subject = @import("stwo_riscv_recursion").air.segment_outer_adapter_manifest;
const focused = @import("cases/recursion/air/tests/segment_outer_adapter_manifest_test.zig");

test "segment V2 outer manifest declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(focused);
}

// Keep focused cases discoverable when a name filter omits the declaration gate.
test {
    _ = focused;
}
