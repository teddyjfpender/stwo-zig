//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/typed_lt_imm_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_branch_lt_witness_test.zig");
    _ = @import("cases/runner/guest_precompile/tests/poseidon2_clock_authority_test.zig");
    _ = @import("cases/runner/guest_precompile/tests/secp256k1_recover_test.zig");
}
