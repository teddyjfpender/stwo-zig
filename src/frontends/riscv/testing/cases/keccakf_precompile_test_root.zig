//! Fast edit-loop root for the Keccak-f precompile authority.

test {
    _ = @import("stwo_riscv_rv32").modules.air_guest_precompile_keccakf_row;
    _ = @import("stwo_riscv_precompiles").modules.air_tests_keccakf_authority_test;
    _ = @import("stwo_riscv_precompiles").modules.air_tests_keccakf_relations_test;
    _ = @import("air/guest_precompile/tests/keccakf_tables_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_multiplicities_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_trace_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_air_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_interaction_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_component_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_table_component_test.zig");
    _ = @import("stwo_riscv_precompiles").modules.air_tests_keccakf_witness_test;
    _ = @import("stwo_riscv_isa").modules.custom0;
    _ = @import("runner/guest_precompile/tests/keccakf_test.zig");
    _ = @import("runner/guest_precompile/tests/keccakf_runner_test.zig");
}
