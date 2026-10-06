//! Focused test root inside the frontend module's import boundary.
comptime {
    _ = @import("recursion/segment_leaf_wrapper_source_projection_v3.zig");
}
