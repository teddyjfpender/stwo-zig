//! Focused P-003 sparse-memory and guest-Poseidon exact-work gate.

comptime {
    _ = @import("prover/poseidon_witness_work_test.zig");
    _ = @import("prover/commitment_witness.zig");
    _ = @import("air/guest_precompile/main_trace.zig");
    _ = @import("prover/main_trace_plan_execution_production_generators.zig");
}
