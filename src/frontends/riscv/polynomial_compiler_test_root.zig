//! Shared direct polynomial compiler and production materialization consumers.
test {
    _ = @import("air/lang/materialization_cost_direct_test.zig");
    _ = @import("air/lang/materialization_direct_program_test.zig");
    _ = @import("air/lang/materialization_fixed_direct_test.zig");
    _ = @import("air/lang/materialization_fixed_cost_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_candidate_test.zig");
}
