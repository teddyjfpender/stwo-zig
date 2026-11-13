//! Product execution-policy half of the preserved services GKR command.
test {
    _ = @import("word16_global_execution/services/gkr_local/v3_execution_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/cpu_compact_role_test.zig");
}
