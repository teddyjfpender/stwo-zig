//! Explicit capacity-native fresh receiver; one shared typed implementation.
const Impl = @import("block_v5_global_receiver_impl_v1.zig").ForStack(@import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true));
pub const Pins = Impl.Pins;
pub const Inputs = Impl.Inputs;
pub const SourcePages = Impl.SourcePages;
pub const VerifiedGlobals = Impl.VerifiedGlobals;
pub const RecursiveLeafPin = Impl.RecursiveLeafPin;
pub const RecursivePins = Impl.RecursivePins;
pub const CompleteBundle = Impl.CompleteBundle;
pub const DetachedForest = Impl.DetachedForest;
pub const ForBackend = Impl.ForBackend;
pub const prepareRecursive = Impl.prepareRecursive;
