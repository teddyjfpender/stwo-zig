//! Resident Cairo base-trace construction.

pub const fixed_tables = @import("cairo_base/fixed_tables.zig");
pub const memory = @import("cairo_base/memory.zig");
pub const multiplicity_feed =
    @import("cairo_base/multiplicity_feed.zig");

test {
    _ = fixed_tables;
    _ = memory;
    _ = multiplicity_feed;
}
