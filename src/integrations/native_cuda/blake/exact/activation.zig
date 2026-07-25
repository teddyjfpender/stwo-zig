//! Product activation boundary for exact CUDA Blake.
//!
//! Host facades are staging contracts only. The product may activate after
//! concrete trace and constraint AOT descriptors are authenticated into its
//! immutable kernel pack and bound by the fixed executor.

pub const State = enum {
    missing_interaction_aot,
    product_ready,
};

pub const state: State = .missing_interaction_aot;

pub fn requireProductReady() !void {
    if (state != .product_ready)
        return error.ExactBlakeCudaInteractionAotUnavailable;
}

test "exact Blake CUDA product remains fail closed before AOT binding" {
    try @import("std").testing.expectError(
        error.ExactBlakeCudaInteractionAotUnavailable,
        requireProductReady(),
    );
}
