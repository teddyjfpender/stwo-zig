//! OP Stack implementation of the RV64 block pipeline hooks. This file is the
//! root of the `rv64_pipeline_hooks` module injected into this product's own
//! pipeline instance; every declaration is statement-level.
const frontend = @import("opstack_frontend_component");
const Profile = @import("stwo_riscv_rv64").execution.execution_profile.Profile;

/// Receipts, CLI help and error context only; never a transcript input.
pub const label = "opstack";
pub const Symbols = frontend.guest_abi.Symbols;
pub const OUTPUT_BYTES = frontend.statement.OUTPUT_BYTES;
/// 32 MiB window less the 4-byte length prefix.
pub const MAX_INPUT_BYTES = frontend.guest_abi.INPUT_CAPACITY_MAX - 4;
/// S1 admits the v3 services ABI only (CPU, Keccak, SHA-256, secp, arith256,
/// bulk memory, sponge). The BN254 sparse-tower profile arrives with RFC-3.
pub fn admitsProfile(profile: Profile) bool {
    return profile == .ethereum_services_v3;
}
pub const loadImage = frontend.guest_abi.load;
pub fn haltFlag(symbols: Symbols) u64 {
    return symbols.halt_flag;
}
/// No extra service families until RFC-3 is decided: base roster, base bytes.
pub const service_families = .{};
