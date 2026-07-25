//! Backend-neutral admission plans for non-recorded Cairo base writers.

pub const catalog = @import("base_writer_plan/catalog.zig");
pub const fixed_tables = @import("base_writer_plan/fixed_tables.zig");
pub const memory = @import("base_writer_plan/memory.zig");

test {
    _ = catalog;
    _ = fixed_tables;
    _ = memory;
}
