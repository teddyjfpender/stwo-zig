comptime {
    @import("std").testing.refAllDeclsRecursive(@import("proving/air/trace_lease_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("preprocessed/trace.zig"));
}
