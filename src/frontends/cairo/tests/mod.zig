//! Focused tests for backend-neutral Cairo frontend semantics.

const std = @import("std");

test {
    _ = @import("official_base_checkpoint.zig");
    _ = @import("official_claim.zig");
    _ = @import("official_input.zig");
    std.testing.refAllDecls(@This());
}
