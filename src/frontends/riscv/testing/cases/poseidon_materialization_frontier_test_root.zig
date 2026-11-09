//! Focused typed-Poseidon materialization and quotient-frontier tests.
//!
//! This root deliberately avoids the full RISC-V test inventory so physical
//! layout experiments retain a short correctness loop.

test {
    _ = @import("air/memory_commitment/poseidon2_narrow_degree3_test.zig");
    _ = @import("air/lang/tests/materialization_cost_test.zig");
    _ = @import("stwo_riscv_memory");
    _ = @import("stwo_riscv_memory");
    _ = @import("air/lang/tests/typed_poseidon2_degree_bounded_trace_test.zig");
    _ = @import("air/lang/tests/typed_poseidon2_degree5_trace_test.zig");
    _ = @import("stwo_riscv_memory");
    _ = @import("stwo_riscv_memory");
    _ = @import("stwo_riscv_memory");
}
