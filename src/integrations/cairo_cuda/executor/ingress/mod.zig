//! Production-shaped Cairo CUDA ingress assembly.

pub const controller_bundle = @import("controller_bundle.zig");
pub const multiplicity_feeds = @import("multiplicity_feeds.zig");
pub const relation_binding = @import("relation_binding.zig");
pub const writer_inputs = @import("writer_inputs.zig");
pub const writer_views = @import("writer_views.zig");
pub const writer_base_tables = @import("writer_base_tables.zig");
pub const writer_preactions = @import("writer_preactions.zig");
pub const writer_binding = @import("writer_binding.zig");

test {
    _ = controller_bundle;
    _ = multiplicity_feeds;
    _ = relation_binding;
    _ = writer_inputs;
}
