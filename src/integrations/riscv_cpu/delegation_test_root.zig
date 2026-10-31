//! Package-root ownership for a registered nested delegation test suite.
test {
    switch (@import("delegation_entry").id) {
        .keccak_test => _ = @import("delegations/keccak/test_root.zig"),
        .keccak_cpu_test => _ = @import("delegations/keccak/cpu_test_root.zig"),
        .keccak_quartet_test => _ = @import("delegations/keccak/quartet_test_root.zig"),
        .secp_test => _ = @import("delegations/secp256k1/test_root.zig"),
        .division_test => _ = @import("delegations/division/test_root.zig"),
        .multiplication_test => _ = @import("delegations/multiplication/test_root.zig"),
        .borrowed_test => _ = @import("delegations/common/borrowed_test_root.zig"),
        else => @compileError("delegation CLI selected as a test root"),
    }
}
