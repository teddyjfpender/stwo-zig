//! Genuine native/caller source verification, statically selected protocol.
const Impl = @import("block_v5_readonly_input_receiver_impl_v1.zig");
pub const ForCapacity = Impl.ForCapacity;
pub const NativeOpen = ForCapacity(false).NativeOpen;
pub const CallerOpen = ForCapacity(false).CallerOpen;
pub const ForBackend = ForCapacity(false).ForBackend;
pub const checkSourceEquation = Impl.checkSourceEquation;
