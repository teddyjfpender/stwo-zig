//! Canonical native extension state; product composites live with their policy.
const generic = @import("stwo_riscv_rv32").execution.guest_precompile.generic_session_state;
pub const ExecutionProfile = @import("stwo_riscv_isa").execution_profile.ExecutionProfile;
pub const ExternalCounts = generic.ExternalCounts;
pub const Empty = generic.Empty;
pub const Poseidon2 = generic.Poseidon2;
pub const Keccakf = generic.Keccakf;
pub fn State(comptime profile: ExecutionProfile) type {
    return @import("stwo_riscv_rv32").execution.default_profile_owner.For(profile).State;
}
