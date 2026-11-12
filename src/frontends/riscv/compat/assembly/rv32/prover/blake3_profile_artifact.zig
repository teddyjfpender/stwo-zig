//! Shared full-width execution-profile artifact framing and fresh verification.
//! Fresh verification derives its key from authenticated metadata and supplied
//! source bytes, without retaining the runner or trusting an embedded proof key.
pub const VerifiedPublic = @import("stwo_riscv_rv32").prover.blake3_verified_public.VerifiedPublic;
pub fn ForProfile(comptime ethereum: bool) type {
    return ForExecutionProfile(if (ethereum) .rv32im_zkvm_ethereum_v1 else .rv32im_zkvm_v1);
}
pub fn ForExecutionProfile(comptime selected_profile: @import("stwo_riscv_isa").execution_profile.ExecutionProfile) type {
    const ethereum = selected_profile == .rv32im_zkvm_ethereum_v1;
    const sha = selected_profile == .rv32im_zkvm_ethereum_sha_v1;
    const is_extended = selected_profile != .rv32im_zkvm_v1;
    if (is_extended and !ethereum and !sha and selected_profile != .rv32im_zkvm_poseidon2_v1) @compileError("unsupported full-width artifact profile");
    return @import("blake3_profile_artifact_owner.zig").ForOwner(struct {
        pub const profile = selected_profile;
        pub const extended = is_extended;
        pub const count_recovery_calls = ethereum;
        pub const manifest = if (sha) @import("stwo_riscv_rv32").prover.blake3_extension_manifest.ForProfile(@import("../../../../prover/blake3_ethereum_sha_profile.zig")) else if (ethereum) @import("../../../../prover/blake3_ethereum_manifest.zig") else if (is_extended) @import("stwo_riscv_rv32").prover.blake3_poseidon_manifest else @import("stwo_riscv_rv32").prover.blake3_execution_manifest;
        pub const codec = if (sha) @import("../../../../prover/blake3_ethereum_sha_proof.zig").codec else if (ethereum) @import("../../../../prover/blake3_ethereum_codec.zig") else if (is_extended) @import("stwo_riscv_rv32").prover.blake3_poseidon_proof.codec else @import("stwo_riscv_rv32").prover.blake3_execution_codec;
        pub const proof_api = if (sha) @import("../../../../prover/blake3_ethereum_sha_proof.zig") else if (ethereum) @import("../../../../prover/blake3_ethereum_proof.zig") else if (is_extended) @import("stwo_riscv_rv32").prover.blake3_poseidon_proof else @import("stwo_riscv_rv32").prover.blake3_execution_proof;
        pub const magic = if (sha) "B3SVART1" else if (ethereum) "B3EVART1" else if (is_extended) "B3PVART1" else "B3RVART1";
    });
}
