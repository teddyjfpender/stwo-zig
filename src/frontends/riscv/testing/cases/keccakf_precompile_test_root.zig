//! Fast edit-loop root for the Keccak-f precompile authority.

test {
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("air/guest_precompile/tests/keccakf_tables_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_multiplicities_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_trace_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_air_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_interaction_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_component_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_table_component_test.zig");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_isa");
    _ = @import("runner/guest_precompile/tests/keccakf_test.zig");
    _ = @import("runner/guest_precompile/tests/keccakf_runner_test.zig");
}
