//! Shared fresh CPU receiver for production qualification and standalone load.
//! No producer-side native/caller/recursive receipt is accepted.
pub const ForCapacity = @import("block_v5_cpu_detached_receive_impl_v1.zig").ForCapacity;
const Default = ForCapacity(false);
pub const Pins = Default.Pins;
pub const Limits = Default.Limits;
pub const verify = Default.verify;
