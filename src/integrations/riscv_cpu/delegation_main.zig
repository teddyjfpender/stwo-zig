//! Package-root ownership for a registered nested delegation CLI.
pub const main = switch (@import("delegation_entry").id) {
    .keccak_fixture => @import("delegations/keccak/fixture_main.zig").main,
    .keccak_verify => @import("delegations/keccak/verify_main.zig").main,
    .secp_fixture => @import("delegations/secp256k1/fixture_main.zig").main,
    .division_degree3_fixture => @import("delegations/division/degree3_main.zig").main,
    .division_verify => @import("delegations/division/verify_main.zig").main,
    .multiplication_verify => @import("delegations/multiplication/verify_main.zig").main,
    else => @compileError("delegation test selected as a CLI root"),
};
