//! Native Plonk binding of the AIR-independent resident proof driver.

const common = @import("../common/driver.zig");

pub const DriverFor = common.DriverFor;
pub const NativeTransaction =
    @import("../../../backends/cuda/runtime/proof_transaction.zig")
        .ResidentProofTransaction;
pub const NativeRuntime =
    @import("../../../backends/cuda/runtime/process_runtime.zig").NativeRuntime;
