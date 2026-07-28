//! Narrow public surface of the concrete Metal backend.
//!
//! This root lives at the common backend ownership level while Metal still
//! delegates selected operations to the scalar CPU implementation. Consumers
//! import this named module instead of reaching into either backend tree.

pub const MetalProverEngine =
    @import("stwo_metal_backend").MetalProverEngine;

test {
    @import("std").testing.refAllDecls(@This());
}
