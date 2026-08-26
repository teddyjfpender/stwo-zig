//! Authoritative capability and release-admission data for Sail RV32IM.

/// RF-01 flips this in the same commit as the artifact release status after
/// every RISC-V soundness and oracle gate passes.
pub const adapter_release_gated = true;
pub const adapter = "sail-rv32im-zkvm-elf";
pub const air = "sail_rv32im_zkvm_v1";
pub const isa = "rv32im";
pub const backend = "cpu";
pub const deferred_reason = "RISC-V formal release contract is not yet fully satisfied";

/// Exact guest profile admitted by the CPU product. The protocol identities
/// match the frontend and Metal product; the placement/runtime policy is
/// deliberately CPU-specific and never implies a device fallback.
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
    .execution_placement = "cpu_scalar_simd_generic_direct_plus_logup_v1",
    .runtime_requirement = "native_cpu_scalar_simd_v1",
    .prove_command = "prove|bench",
    .verify_command = "verify",
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

test "CPU guest capability is exact and cannot fall back" {
    const std = @import("std");
    try std.testing.expectEqualStrings("rv32im-zkvm-poseidon2-v1", guest_poseidon2.profile);
    try std.testing.expectEqual(@as(u16, 1), guest_poseidon2.version);
    try std.testing.expectEqualStrings(
        "stwo.poseidon2-m31.permute-in-place@1",
        guest_poseidon2.capability,
    );
    try std.testing.expectEqualStrings(
        "cpu_scalar_simd_generic_direct_plus_logup_v1",
        guest_poseidon2.execution_placement,
    );
    try std.testing.expect(!guest_poseidon2.backend_fallback_allowed);
}
