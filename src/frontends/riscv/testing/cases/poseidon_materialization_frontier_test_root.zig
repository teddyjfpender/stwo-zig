//! Focused typed-Poseidon materialization and quotient-frontier tests.
//!
//! This root deliberately avoids the full RISC-V test inventory so physical
//! layout experiments retain a short correctness loop.

test {
    _ = @import("air/memory_commitment/poseidon2_narrow_degree3_test.zig");
    _ = @import("air/lang/tests/materialization_cost_test.zig");
    _ = @import("stwo_riscv_memory").modules.typed_tests_typed_poseidon2_degree_bounded_candidate_test;
    _ = @import("stwo_riscv_memory").modules.typed_tests_typed_poseidon2_degree_bounded_component_test;
    _ = @import("air/lang/tests/typed_poseidon2_degree_bounded_trace_test.zig");
    _ = @import("air/lang/tests/typed_poseidon2_degree5_trace_test.zig");
    _ = @import("stwo_riscv_memory").modules.prover_provider_order_component;
    _ = @import("stwo_riscv_memory").modules.air_poseidon2_air;
    _ = @import("stwo_riscv_memory").modules.primitives_recursion_poseidon2_channel;
}
