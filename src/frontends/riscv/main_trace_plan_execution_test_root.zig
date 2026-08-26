//! Focused compile/run root for the prepared Tree-1 generation slice.

comptime {
    _ = @import("prover/main_trace_plan_execution_test.zig");
    _ = @import("prover/main_trace_plan_execution_production.zig");
    _ = @import("prover/main_trace_plan_execution_production_test.zig");
    _ = @import("prover/main_witness_work.zig");
    _ = @import("prover/tree2_main_source.zig");
}
