//! Focused shared-store ownership and transport checks; no proof invocation.
test {
    _ = @import("prover/block_v5_native_capacity_store_test.zig");
    _ = @import("prover/block_v5_native_capacity_fused_transport_test_v1.zig");
}
