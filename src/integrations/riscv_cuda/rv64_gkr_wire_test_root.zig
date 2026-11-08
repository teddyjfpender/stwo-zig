//! Canonical local-GKR receipt and child-wire codec parity.
test {
    _ = @import("rv64/jobs/native_gkr_wire.zig");
    _ = @import("rv64/jobs/native_leaf_wire.zig");
    _ = @import("rv64/jobs/native_leaf_wire_gpu_test.zig");
    _ = @import("rv64/jobs/outer_packed_class_test.zig");
}
