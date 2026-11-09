//! Focused edit-loop root for the combined Ethereum runner profile.

test {
    _ = @import("stwo_riscv_frontend").isa.custom0;
    _ = @import("stwo_riscv_frontend").isa.secp256k1_recovery_memory_abi;
    _ = @import("stwo_riscv_frontend").isa.execution_profile;
    _ = @import("runner/guest_precompile/tests/ethereum_runner_test.zig");
    _ = @import("stwo_riscv_frontend").runner.guest_precompile.secp256k1_recover_call_buffer;
    _ = @import("../../../../frontends/riscv/runner/guest_precompile/tests/secp256k1_recover_v1_test.zig");
}
