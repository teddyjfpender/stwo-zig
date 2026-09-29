//! Explicit discovery for borrowed witness destination and custody checks.
comptime {
    @import("std").testing.refAllDeclsRecursive(@import("witness/implicit_interaction_sources.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("proving/base_columns_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("witness/final_storage_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("witness/gathered_materialization_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("witness/gathered_inputs.zig"));
}
