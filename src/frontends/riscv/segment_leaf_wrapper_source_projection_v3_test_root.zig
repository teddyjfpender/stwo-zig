//! Focused test root inside the frontend module's import boundary.
comptime {
    _ = @import("recursion/segment_leaf_wrapper_source_projection_v3.zig");
    _ = @import("recursion/air/segment_leaf_wrapper_roster_v3_v2.zig");
    _ = @import("recursion/segment_leaf_wrapper_protocol_v3.zig");
}
