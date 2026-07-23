//! Fail-closed resident CUDA runtime errors.

pub const Error = error{
    AotPackAbsent,
    BuildIdentityAbsent,
    ContextClosed,
    ContextMismatch,
    CudaFailure,
    DeviceArchitectureMismatch,
    DeviceBufferLive,
    DeviceUnavailable,
    EmptyAllocation,
    InvalidDeviceArchitecture,
    InvalidDeviceOrdinal,
    InvalidState,
    KernelPathUnused,
    NullDevicePointer,
    NullExecutionContext,
    NullExecutionStream,
    SizeOverflow,
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
