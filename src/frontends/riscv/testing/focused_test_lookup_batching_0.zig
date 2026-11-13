//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/lookup_batch_planner_test.zig");
    _ = @import("cases/air/lang/tests/lookup_batch_execution_test.zig");
    _ = @import("cases/air/lang/tests/lookup_polynomial_program_test.zig");
    _ = @import("cases/air/lang/tests/lookup_physical_manifest_test.zig");
    _ = @import("cases/air/lang/tests/lookup_physical_manifest_assembly_test.zig");
    _ = @import("cases/air/lang/tests/lookup_batch_performance_test.zig");
}
