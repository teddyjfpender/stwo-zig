//! Focused tests for backend-neutral Cairo frontend semantics.

const std = @import("std");

test {
    _ = @import("base_trace_arena.zig");
    _ = @import("feed_geometry_oracle.zig");
    _ = @import("official_base_checkpoint.zig");
    _ = @import("official_claim.zig");
    _ = @import("official_input.zig");
    _ = @import("official_interaction_checkpoint.zig");
    _ = @import("official_live_geometry.zig");
    _ = @import("official_preprocessed.zig");
    _ = @import("preprocessed_cache_eviction.zig");
    std.testing.refAllDecls(@This());
}
