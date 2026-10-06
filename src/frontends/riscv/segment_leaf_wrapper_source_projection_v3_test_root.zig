//! Focused test root inside the frontend module's import boundary.
comptime {
    _ = @import("recursion/segment_leaf_wrapper_source_projection_v3.zig");
    _ = @import("recursion/air/segment_leaf_wrapper_roster_v3_v2.zig");
    _ = @import("recursion/segment_leaf_wrapper_protocol_v3.zig");
    _ = @import("recursion/ethereum_leaf_link_program_v3.zig");
    _ = @import("recursion/ethereum_leaf_direct_public_authority_v3.zig");
    _ = @import("recursion/segment_leaf_wrapper_source_projection_direct_v3.zig");
    _ = @import("recursion/air/segment_v2_tree0_field_link_direct_v4.zig");
    _ = @import("recursion/air/transcript_program_v2_field_bridge_v4.zig");
    _ = @import("recursion/segment_leaf_wrapper_las2_boundary_v4.zig");
}
