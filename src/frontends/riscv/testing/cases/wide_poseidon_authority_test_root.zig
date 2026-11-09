//! Focused wide-Poseidon equation admission and shared witness authority.
test {
    _ = @import("air/lang/tests/typed_poseidon2_wide_test.zig");
    _ = @import("stwo_riscv_memory").modules.typed_typed_poseidon2_authority;
    _ = @import("stwo_riscv_memory").modules.typed_tests_typed_poseidon2_relations_test;
}
