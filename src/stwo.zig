//! Root module for stwo-zig.
const std = @import("std");

pub const core = @import("core/mod.zig");
pub const prover = @import("prover/mod.zig");
pub const tracing = @import("tracing/mod.zig");

test {
    // Ensure `zig build test` at least compiles the root graph eagerly.
    std.testing.refAllDecls(@This());
}
