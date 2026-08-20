//! Authoritative capability and release-admission data for Sail RV32IM on the
//! fail-closed Metal backend.
//!
//! Every string below except `backend` is deliberately byte-identical to
//! `src/products/riscv_cpu/capabilities.zig`: the RISC-V *adapter* release gate
//! is a property of the AIR, not of the commitment backend, so both product
//! lanes must take the same admission path and report the same adapter, AIR and
//! ISA identity. Only the backend token distinguishes them, and it is the single
//! value that flows into this product's registry `backends` list.
//!
//! The two files are intentionally not shared: importing the CPU product's
//! capabilities here would put `src/products/riscv_cpu` inside the Metal
//! product's source closure, which the closure gate forbids.

/// RF-01 flips this in the same commit as the artifact release status after
/// every RISC-V soundness and oracle gate passes. It must stay in lockstep with
/// the CPU product's value so `riscv_cli_admission` needs only a backend
/// substitution to admit this CLI.
pub const adapter_release_gated = true;
pub const adapter = "sail-rv32im-zkvm-elf";
pub const air = "sail_rv32im_zkvm_v1";
pub const isa = "rv32im";
pub const backend = "metal";
pub const deferred_reason = "RISC-V formal release contract is not yet fully satisfied";

/// The sole guest extension this product admits. This is not a wildcard guest
/// capability: every identity is compared against the frontend and integration
/// authorities by product tests, and the CLI exposes only the two named routes.
pub const GuestPoseidon2Profile = struct {
    profile: []const u8,
    version: u16,
    capability: []const u8,
    manifest_sha256: []const u8,
    caller_component: []const u8,
    provider_component: []const u8,
    execution_placement: []const u8,
    runtime_requirement: []const u8,
    prove_command: []const u8,
    verify_command: []const u8,
    backend_fallback_allowed: bool,
};

pub const guest_poseidon2 = GuestPoseidon2Profile{
    .profile = "rv32im-zkvm-poseidon2-v1",
    .version = 1,
    .capability = "stwo.poseidon2-m31.permute-in-place@1",
    .manifest_sha256 = "265df524ca93ba5f240aec9e5ce2f9f616c302850410ee812c220aa3e59fb891",
    .caller_component = "riscv_guest_poseidon2_caller_v1",
    .provider_component = "riscv_guest_poseidon2_provider_v1",
    .execution_placement = "reviewed_generic_direct_plus_logup_v1",
    .runtime_requirement = "authenticated_core_aot_v2",
    .prove_command = "guest-poseidon2-prove",
    .verify_command = "guest-poseidon2-verify",
    .backend_fallback_allowed = false,
};

pub fn requireAdmission(experimental: bool) !void {
    if (adapter_release_gated) {
        if (experimental) return error.ExperimentalFlagAfterPromotion;
    } else if (!experimental) {
        return error.ExperimentalFlagRequired;
    }
}

test "staged admission is explicit and fail closed" {
    const std = @import("std");
    if (adapter_release_gated) {
        try requireAdmission(false);
        try std.testing.expectError(error.ExperimentalFlagAfterPromotion, requireAdmission(true));
    } else {
        try requireAdmission(true);
        try std.testing.expectError(error.ExperimentalFlagRequired, requireAdmission(false));
    }
}

test "this product can only ever report the Metal backend" {
    const std = @import("std");
    try std.testing.expectEqualStrings("metal", backend);
}

test "guest capability names one exact versioned profile and no fallback" {
    const std = @import("std");
    try std.testing.expectEqualStrings(
        "rv32im-zkvm-poseidon2-v1",
        guest_poseidon2.profile,
    );
    try std.testing.expectEqual(@as(u16, 1), guest_poseidon2.version);
    try std.testing.expectEqualStrings(
        "stwo.poseidon2-m31.permute-in-place@1",
        guest_poseidon2.capability,
    );
    try std.testing.expect(!guest_poseidon2.backend_fallback_allowed);
}
