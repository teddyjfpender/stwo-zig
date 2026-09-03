//! Focused typed-Poseidon materialization and quotient-frontier tests.
//!
//! This root deliberately avoids the full RISC-V test inventory so physical
//! layout experiments retain a short correctness loop.

test {
    _ = @import("air/lang/materialization_cost_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_candidate_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_component_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_backend_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_trace_test.zig");
}
