//! Focused edit-loop root for the combined Ethereum runner profile.

test {
    _ = @import("stwo_riscv_isa");
    _ = @import("compat/product_tree/isa/ethereum_signer_recovery.zig");
    _ = @import("stwo_riscv_isa");
    _ = @import("runner/guest_precompile/tests/ethereum_runner_test.zig");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_testing");
}
