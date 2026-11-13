//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("stwo_riscv_precompiles").recovery_abi;
    _ = @import("stwo_riscv_precompiles").runner.secp256k1_recover_call_buffer;
}
