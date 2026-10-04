//! Shared direct polynomial compiler and production materialization consumers.
test {
    _ = @import("air/lang/tests/materialization_cost_direct_test.zig");
    _ = @import("air/lang/tests/materialization_direct_program_test.zig");
    _ = @import("air/lang/tests/materialization_fixed_direct_test.zig");
    _ = @import("air/lang/tests/materialization_fixed_cost_test.zig");
    _ = @import("air/lang/tests/typed_poseidon2_degree_bounded_candidate_test.zig");
}
