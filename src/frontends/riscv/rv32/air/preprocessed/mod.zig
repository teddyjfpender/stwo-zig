//! Preprocessed lookup tables for the RISC-V AIR.
//!
//! These constant tables are used by LogUp relations to verify that witness
//! values satisfy range and bitwise constraints without re-deriving results
//! inside the AIR. Each table is generated once and shared across all proofs.

pub const bitwise = @import("bitwise.zig");
pub const range_check = @import("range_check.zig");

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
