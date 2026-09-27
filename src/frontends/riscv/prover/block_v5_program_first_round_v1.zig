//! Shared typed implementation with unchanged explicit legacy exports.
const Impl = @import("block_v5_program_first_round_impl_v1.zig");
pub const ForCapacity = Impl.ForCapacity;
pub const ExtensionPin = Impl.ExtensionPin;
pub const ForBackend = ForCapacity(false).ForBackend;
