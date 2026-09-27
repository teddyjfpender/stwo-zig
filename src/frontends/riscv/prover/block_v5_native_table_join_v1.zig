//! Explicit NativeV3 compatibility fresh receiver; one shared typed implementation.
const Impl = @import("block_v5_native_table_join_impl_v1.zig").ForStack(@import("block_v5_native_receiver_stack_v1.zig").ForCapacity(false));
pub const Pins = Impl.Pins;
pub const Loader = Impl.Loader;
pub const Joined = Impl.Joined;
pub const ForBackend = Impl.ForBackend;
