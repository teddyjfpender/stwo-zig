//! Fail-closed resident CUDA runtime errors.

pub const Error = error{
    ArenaSlotMissing,
    AotReceiptMismatch,
    AllocationOutsideIngress,
    AotPackAbsent,
    ArgumentCountMismatch,
    BuildIdentityAbsent,
    ContextClosed,
    ContextMismatch,
    CudaFailure,
    DeviceArchitectureMismatch,
    DeviceBufferLive,
    DeviceUnavailable,
    DuplicateArenaSlot,
    EmptyArenaPlan,
    EmptyAllocation,
    HostReadOutsideProofAssembly,
    HostWriteOutsideIngress,
    InvalidDeviceArchitecture,
    InvalidDeviceOrdinal,
    InvalidArenaRequirement,
    InvalidDeviceAddress,
    InvalidKernelDescriptor,
    InvalidState,
    KernelPathUnused,
    NullDevicePointer,
    NullExecutionContext,
    NullExecutionStream,
    SizeOverflow,
    StageAlreadyActive,
    StageNotActive,
    StageOrderViolation,
    StrictAotViolation,
};

pub fn check(status: c_int) Error!void {
    if (status != 0) return error.CudaFailure;
}

test "only CUDA success status is accepted" {
    try check(0);
    try @import("std").testing.expectError(error.CudaFailure, check(1));
    try @import("std").testing.expectError(error.CudaFailure, check(-1));
}
