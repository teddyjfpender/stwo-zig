//! Canonical Stwo-Cairo preprocessed columns.

pub const columns = @import("columns.zig");
pub const pedersen_table = @import("pedersen_table.zig");

test {
    _ = columns;
}
