//! Compatible profile-selecting facade; generic lifecycle lives in the RV32 child.
const generic = @import("stwo_riscv_rv32").runner_session_owner;
const profiles = @import("session_profile_owners.zig");
pub const ExecutionProfile = generic.ExecutionProfile;
pub const HostInterface = generic.HostInterface;
pub const SegmentClockFrame = generic.SegmentClockFrame;
pub const TraceRetention = generic.TraceRetention;
pub const RetirementObserverV1 = generic.RetirementObserverV1;
pub const PreRetirementBoundaryV1 = generic.PreRetirementBoundaryV1;
pub const PreRetirementBoundaryObserverV1 = generic.PreRetirementBoundaryObserverV1;
pub const SessionOptions = generic.SessionOptions;

pub fn ConfiguredSegmentResult(comptime profile: ExecutionProfile) type { return profiles.For(profile, false, false).SegmentResult; }

pub fn ExecutionSession(comptime profile: ExecutionProfile) type {
    return ExecutionSessionWithPolicy(profile, false, false);
}

pub fn EthereumStackSwapCandidateExecutionSessionV1() type {
    return ExecutionSessionWithPolicy(.rv32im_zkvm_ethereum_v1, true, false);
}

pub fn EthereumBulkMemcpyCandidateExecutionSessionV1() type {
    return ExecutionSessionWithPolicy(.rv32im_zkvm_ethereum_v1, false, true);
}

pub fn EthereumCombinedCandidateExecutionSessionV1() type {
    return ExecutionSessionWithPolicy(.rv32im_zkvm_ethereum_v1, true, true);
}

fn ExecutionSessionWithPolicy(comptime profile: ExecutionProfile, comptime stack_swap: bool, comptime bulk_memcpy: bool) type { return generic.ForOwner(profiles.For(profile, stack_swap, bulk_memcpy)); }
