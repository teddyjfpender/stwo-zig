//! Explicit capacity-native fresh receiver; one shared typed implementation.
const Impl = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(@import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true));
pub const ExtensionPin = Impl.ExtensionPin;
pub const Pins = Impl.Pins;
pub const Loader = Impl.Loader;
pub const ExecutionBytes = Impl.ExecutionBytes;
pub const OpenPartition = Impl.OpenPartition;
pub const ForBackend = Impl.ForBackend;
