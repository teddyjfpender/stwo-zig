//! Bounded column reconstruction and recursive row custody, no segment proofs.
comptime {
    _ = @import("block_v5_witness_columns_store_test_root.zig");
    _ = @import("block_v5_caller_columns_stage_test_root.zig");
    _ = @import("block_v5_recursive_direct_columns_test_root.zig");
}
