//! Discover generator behavior within the integration package boundary.
comptime {
    @import("std").testing.refAllDeclsRecursive(@import("eval_codegen.zig"));
}
