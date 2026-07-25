//! Product activation boundary for exact CUDA Blake.
//!
//! Host facades are staging contracts only. The product may activate after
//! concrete trace and constraint AOT descriptors are authenticated into its
//! immutable kernel pack and bound by the fixed executor.

pub const State = enum {
    structural_only,
    product_ready,
};

pub const state: State = .structural_only;

pub fn requireProductReady() !void {
    if (state != .product_ready)
        return error.ExactBlakeCudaAotBindingsUnavailable;
}

test "exact Blake CUDA product remains fail closed before AOT binding" {
    try @import("std").testing.expectError(
        error.ExactBlakeCudaAotBindingsUnavailable,
        requireProductReady(),
    );
}
