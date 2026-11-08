//! Cross-layer parity evidence bound to the pinned Rust Stwo oracle.
//!
//! These tests intentionally depend on core, prover, and example modules. They
//! belong to the deep conformance graph rather than any individual layer.

test {
    _ = @import("vectors.zig");
}
