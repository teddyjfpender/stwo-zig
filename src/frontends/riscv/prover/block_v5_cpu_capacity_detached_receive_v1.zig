//! Explicit typed capacity complete-bundle transport.
const Impl = @import("block_v5_cpu_detached_receive_v1.zig").ForCapacity(true);
pub const Pins = Impl.Pins;
pub const Limits = Impl.Limits;
pub const verify = Impl.verify;
