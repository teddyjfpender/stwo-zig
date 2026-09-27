//! Explicit typed GLOBAL readonly flavor; original native/capacity proof types,
//! template catalogues, caller arithmetic and exact forest codecs are unchanged.
pub fn ForCapacity(comptime capacity_native: bool) type {
    const Base = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(capacity_native);
    const Policy = @import("block_v5_readonly_input_global_memory_policy_v2.zig");
    const ProgramStack = struct {
        pub const capacity = capacity_native;
        pub const Catalog = Base.Catalog;
        pub const Fused = Base.Fused;
        pub const Source = Base.FusedSource;
        pub const Receiver = Base.FusedReceiver;
    };
    return struct {
        pub const is_capacity = capacity_native;
        pub const Native = Base.Native;
        pub const Template = Base.Template;
        pub const Catalog = Base.Catalog;
        pub const Fused = Base.Fused;
        pub const FusedReceiver = Base.FusedReceiver;
        pub const FusedSource = Base.FusedSource;
        pub const ProjectionReceipt = Base.ProjectionReceipt;
        pub const NativeRecursive = Base.NativeRecursive;
        pub const LeafProtocol = Base.LeafProtocol;
        pub const LeafBus = Base.LeafBus;
        pub const Exact = Base.Exact;
        pub const Manifest = Base.Manifest;
        pub const Programs = @import("block_v5_program_native_batch_common_v1.zig").ForNativeStackReadonly(Base.Native, Base.Template, @import("block_v5_native_public_admission_v1.zig").Admission, true, true, ProgramStack, Policy);
    };
}
