//! Focused edit-loop root for the combined Ethereum runner profile.

test {
    _ = @import("stwo_riscv_isa").modules.custom0;
    _ = @import("isa/ethereum_signer_recovery.zig");
    _ = @import("stwo_riscv_isa").modules.execution_profile;
    _ = @import("runner/guest_precompile/tests/ethereum_runner_test.zig");
    _ = @import("stwo_riscv_precompiles").modules.runner_secp256k1_recover_call_buffer;
    _ = @import("stwo_riscv_testing").modules.cases_runner_guest_precompile_tests_secp256k1_recover_test;
}
