//! Native/Poseidon/Keccak selection; product policies supply their own owner.
const generic = @import("stwo_riscv_rv32").execution.session_owner;
const profiles = @import("stwo_riscv_rv32").execution.default_profile_owner;
pub const ExecutionProfile = generic.ExecutionProfile;
pub const HostInterface = generic.HostInterface;
pub const SegmentClockFrame = generic.SegmentClockFrame;
pub const TraceRetention = generic.TraceRetention;
pub const RetirementObserverV1 = generic.RetirementObserverV1;
pub const PreRetirementBoundaryV1 = generic.PreRetirementBoundaryV1;
pub const PreRetirementBoundaryObserverV1 = generic.PreRetirementBoundaryObserverV1;
pub const SessionOptions = generic.SessionOptions;
pub fn ConfiguredSegmentResult(comptime profile: ExecutionProfile) type {
    return profiles.For(profile).SegmentResult;
}
pub fn ExecutionSession(comptime profile: ExecutionProfile) type {
    return generic.ForOwner(profiles.For(profile));
}
