//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/memory_commitment/poseidon2_narrow_degree3_test.zig");
    _ = @import("cases/air/lang/tests/materialization_cost_test.zig");
    _ = @import("cases/air/lang/tests/typed_poseidon2_degree_bounded_trace_test.zig");
    _ = @import("cases/air/lang/tests/typed_poseidon2_degree5_trace_test.zig");
}
