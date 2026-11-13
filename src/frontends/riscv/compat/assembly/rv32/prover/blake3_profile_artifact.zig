//! Native/Poseidon profile selection over the canonical full-width framing owner.
pub const ForOwner = @import("blake3_profile_artifact_owner.zig").ForOwner;
pub const VerifiedPublic = @import("stwo_riscv_rv32").prover.blake3_verified_public.VerifiedPublic;
pub fn ForProfile(comptime ethereum: bool) type {
    return ForExecutionProfile(if (ethereum) .rv32im_zkvm_ethereum_v1 else .rv32im_zkvm_v1);
}
pub fn ForExecutionProfile(comptime selected_profile: @import("stwo_riscv_isa").execution_profile.ExecutionProfile) type {
    const is_extended = selected_profile == .rv32im_zkvm_poseidon2_v1;
    if (selected_profile != .rv32im_zkvm_v1 and !is_extended) @compileError("unsupported full-width artifact profile");
    const native = @import("stwo_riscv_rv32").prover;
    return ForOwner(struct {
        pub const profile = selected_profile;
        pub const extended = selected_profile == .rv32im_zkvm_poseidon2_v1;
        pub const count_recovery_calls = false;
        pub const manifest = if (extended) native.blake3_poseidon_manifest else native.blake3_execution_manifest;
        pub const codec = if (extended) native.blake3_poseidon_proof.codec else native.blake3_execution_codec;
        pub const proof_api = if (extended) native.blake3_poseidon_proof else native.blake3_execution_proof;
        pub const magic = if (extended) "B3PVART1" else "B3RVART1";
    });
}
