//! Focused tests for backend-neutral Cairo frontend semantics.

const std = @import("std");

test {
    _ = @import("official_base_checkpoint.zig");
    _ = @import("official_claim.zig");
    _ = @import("official_input.zig");
    _ = @import("official_interaction_checkpoint.zig");
    _ = @import("official_live_geometry.zig");
    _ = @import("official_preprocessed.zig");
    std.testing.refAllDecls(@This());
}
