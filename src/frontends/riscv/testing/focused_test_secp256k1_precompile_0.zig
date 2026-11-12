//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/guest_precompile/tests/secp256k1_recovery_caller_test.zig");
    _ = @import("cases/air/guest_precompile/tests/secp256k1_component_test.zig");
}
