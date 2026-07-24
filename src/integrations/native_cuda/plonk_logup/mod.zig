//! Activation-disabled exact Plonk/LogUp Native CUDA integration.

pub const geometry = @import("geometry.zig");
pub const layout = @import("layout.zig");
pub const oods = @import("oods.zig");
pub const relation = @import("relation.zig");
pub const topology = @import("topology.zig");

/// Release activation remains false until the resident proof matches the CPU
/// canonical bytes, passes the pinned Rust verifier, and reports no fallback.
pub const release_enabled = false;

test {
    _ = geometry;
    _ = layout;
    _ = oods;
    _ = relation;
    _ = topology;
}
