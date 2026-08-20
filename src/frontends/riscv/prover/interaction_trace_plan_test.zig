//! R-003 interaction-trace plan test-suite root.

test {
    _ = @import("interaction_trace_plan_core_test.zig");
    _ = @import("interaction_trace_plan_performance_test.zig");
}
