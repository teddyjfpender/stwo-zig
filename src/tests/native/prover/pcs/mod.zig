//! Native backend PCS integration tests grouped by protocol phase.

test {
    _ = @import("commitment_test.zig");
    _ = @import("lifting_test.zig");
    _ = @import("opening_test.zig");
}
