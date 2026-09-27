//! Genuine complete ORIGINAL closure with internal fresh GLOBAL source/provider
//! verification. This additive flavor never accepts detached Open DTOs as inputs.
pub fn ForCapacity(comptime capacity_native: bool) type {
    const Stack = @import("block_v5_readonly_input_global_receiver_stack_v2.zig").ForCapacity(capacity_native);
    const Impl = @import("block_v5_global_receiver_impl_v1.zig").ForStackReadonly(Stack, @import("block_v5_readonly_input_global_memory_policy_v2.zig"));
    return struct {
        pub const Pins = Impl.Pins;
        pub const Inputs = Impl.Inputs;
        pub const VerifiedGlobals = Impl.VerifiedGlobals;
        pub const RecursiveLeafPin = Impl.RecursiveLeafPin;
        pub const RecursivePins = Impl.RecursivePins;
        pub const CompleteBundle = Impl.CompleteBundle;
        pub const DetachedForest = Impl.DetachedForest;
        pub const ForBackend = Impl.ForBackend;
        pub const SourcePages = Impl.SourcePages;
        pub const prepareRecursive = Impl.prepareRecursive;
    };
}
