//! Unchanged cases from failed full-suite run 42645009580; tracked in #330.
//! This diagnostic supplements the complete frontend acceptance gate.
test {
    _ = @import("recursion/air/tests/range_check_8_8_bridge_test.zig");
    _ = @import("air/lang/tests/typed_branch_eq_witness_performance_test.zig");
    _ = @import("air/lang/tests/typed_branch_lt_witness_performance_test.zig");
    _ = @import("air/lang/tests/typed_div_witness_test.zig");
    _ = @import("air/lang/tests/typed_fence_witness_test.zig");
    _ = @import("air/lang/tests/typed_load_store_witness_test.zig");
    _ = @import("air/lang/tests/typed_lt_imm_witness_test.zig");
    _ = @import("air/lang/tests/typed_lt_reg_witness_performance_test.zig");
    _ = @import("air/lang/tests/typed_shifts_imm_witness_performance_test.zig");
    _ = @import("air/lang/tests/opcode_composition_manifest_test.zig");
    _ = @import("prover/tests/blake3_commitment_components_test.zig");
    _ = @import("prover/tests/blake3_continuation_witness_test.zig");
}
