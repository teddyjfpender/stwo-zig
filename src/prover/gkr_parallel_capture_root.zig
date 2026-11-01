//! External exact pre-change capture; baseline source is supplied by the command.
pub const baseline = @import("baseline");
test {
    _ = @import("lookups/packed_rows_test.zig");
    _ = @import("lookups/parallel_rows_test.zig");
}
