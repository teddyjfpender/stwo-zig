//! Focused edit-loop root for the combined Ethereum runner profile.

test {
    _ = @import("../../../../frontends/riscv/isa/custom0.zig");
    _ = @import("../../../../frontends/riscv/isa/secp256k1_recovery_memory_abi.zig");
    _ = @import("../../../../frontends/riscv/isa/execution_profile.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_runner_test.zig");
    _ = @import("../../../../frontends/riscv/runner/guest_precompile/secp256k1_recover_call_buffer.zig");
    _ = @import("../../../../frontends/riscv/runner/guest_precompile/tests/secp256k1_recover_v1_test.zig");
}
