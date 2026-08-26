//! Focused A-014 planner and row-execution gate.

test {
    _ = @import("air/lang/lookup_batch_planner_test.zig");
    _ = @import("air/lang/lookup_batch_execution_test.zig");
    _ = @import("air/lang/lookup_polynomial_program_v2_test.zig");
    _ = @import("air/lang/lookup_physical_manifest_v2_test.zig");
    _ = @import("air/lang/lookup_physical_manifest_v2_assembly_test.zig");
    _ = @import("air/lang/lookup_batch_performance_test.zig");
}
