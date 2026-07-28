//! Wide-Fibonacci binding of the AIR-independent resident proof driver.

const common = @import("../common/driver.zig");

pub const DriverFor = common.DriverFor;
pub const NativeTransaction =
    @import("stwo_cuda_backend").runtime.proof_transaction
        .ResidentProofTransaction;
pub const NativeRuntime =
    @import("stwo_cuda_backend").runtime.process_runtime.NativeRuntime;
