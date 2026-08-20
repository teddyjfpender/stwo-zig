//! Focused compile/run root for the prepared Tree-2 interaction epoch.

comptime {
    _ = @import("prover/interaction_trace_plan_test.zig");
    _ = @import("prover/interaction_trace_plan_execution_production.zig");
    _ = @import("prover/interaction_trace_prepared_logup.zig");
}
