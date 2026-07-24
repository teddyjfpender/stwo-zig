//! Fail-closed resident CUDA runtime errors.

pub const Error = error{
    ArenaSlotMissing,
    AotReceiptMismatch,
    AllocationOutsideIngress,
    AllocationRegistryFull,
    AotPackAbsent,
    ArgumentCountMismatch,
    BuildIdentityAbsent,
    ContextClosed,
    ContextMismatch,
    CudaFailure,
    DeviceArchitectureMismatch,
    DeviceBufferLive,
    DeviceUnavailable,
    DuplicateOutputIndex,
    DuplicateArenaSlot,
    EmptyArenaPlan,
    EmptyAllocation,
    HostReadOutsideProofAssembly,
    HostWriteOutsideIngress,
    InsufficientDeviceMemory,
    InvalidDeviceArchitecture,
    InvalidDeviceOrdinal,
    InvalidDeviceMemorySnapshot,
    InvalidArenaRequirement,
    InvalidDeviceAddress,
    InvalidExecutionLaneCount,
    InvalidDecommitmentAssembly,
    InvalidKernelDescriptor,
    InvalidFoldCount,
    InvalidOutputIndex,
    InvalidState,
    KernelPathUnused,
    NullDevicePointer,
    NullExecutionContext,
    NullExecutionStream,
    OutOfMemory,
    OverlappingDeviceRange,
    SizeOverflow,
    StageAlreadyActive,
    StageNotActive,
    StageOrderViolation,
    StrictAotViolation,
    ThreadOwnershipViolation,
};

pub fn check(status: c_int) Error!void {
    if (status != 0) return error.CudaFailure;
}

test "only CUDA success status is accepted" {
    try check(0);
    try @import("std").testing.expectError(error.CudaFailure, check(1));
    try @import("std").testing.expectError(error.CudaFailure, check(-1));
}
