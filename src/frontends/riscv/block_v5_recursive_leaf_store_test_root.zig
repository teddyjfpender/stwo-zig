//! Literal nonproof transport/admission only; no STARK construction or segments.
comptime {
    _ = @import("prover/block_v5_recursive_execution_leaf_store_test_v1.zig");
    _ = @import("prover/block_v5_recursive_provider_transport_test_v1.zig");
    _ = @import("block_v5_recursive_leaf_store_codegen.zig");
}
test "leaf store root" {}
