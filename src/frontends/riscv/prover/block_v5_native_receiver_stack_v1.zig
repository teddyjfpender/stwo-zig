//! Closed, typed fresh-receiver stacks. Capacity proofs/receipts never pass
//! through the legacy native protocol, codec, or separate-projection hooks.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        pub const is_capacity = capacity;
        pub const Programs = if (capacity) @import("block_v5_program_native_capacity_batch_receiver_v1.zig") else @import("block_v5_program_native_batch_receiver_v3.zig");
        pub const Native = if (capacity) @import("block_v5_native_capacity_proof_v1.zig") else @import("block_v5_native_execution_proof_v3.zig");
        pub const Template = if (capacity) @import("block_v5_native_capacity_protocol_v1.zig") else @import("block_v5_native_template_protocol_v3.zig");
        pub const Catalog = if (capacity) @import("block_v5_native_capacity_catalog_v1.zig") else @import("block_v5_native_template_catalog_v1.zig");
        pub const Fused = if (capacity) @import("block_v5_native_capacity_fused_proof_v1.zig") else @import("block_v5_native_projection_fused_proof_v2.zig");
        pub const FusedReceiver = if (capacity) @import("block_v5_native_capacity_fused_receiver_v1.zig") else @import("block_v5_native_projection_fused_receiver_v2.zig");
        pub const FusedSource = if (capacity) @import("block_v5_native_capacity_fused_source_v1.zig") else @import("block_v5_native_projection_fused_source_v1.zig");
        pub const ProjectionReceipt = if (capacity) Fused.ProjectionReceipt else @import("block_v5_native_projection_fused_proof_v1.zig").VerifiedReceipt;
        pub const NativeRecursive = if (capacity) @import("block_v5_native_capacity_recursive_admission_v1.zig") else @import("block_v5_native_recursive_admission_v3.zig");
        pub const LeafProtocol = if (capacity) @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig") else @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
        pub const LeafBus = if (capacity) @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig") else @import("../recursion/block_v5_recursive_public_bus_v1.zig");
        pub const Exact = if (capacity) @import("../recursion/block_v5_capacity_exact_forest_receiver_v1.zig") else @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
        pub const Manifest = if (capacity) @import("block_v5_capacity_open_forest_manifest_v1.zig") else @import("block_v5_open_forest_manifest_v1.zig");
    };
}
