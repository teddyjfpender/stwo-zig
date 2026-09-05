//! Focused edit-loop root for the combined Ethereum runner profile.

test {
    _ = @import("isa/custom0.zig");
    _ = @import("isa/ethereum_signer_recovery.zig");
    _ = @import("isa/execution_profile.zig");
    _ = @import("runner/guest_precompile/ethereum_runner_test.zig");
    _ = @import("runner/guest_precompile/secp256k1_recover_call_buffer.zig");
    _ = @import("runner/guest_precompile/secp256k1_recover_v1_test.zig");
}
