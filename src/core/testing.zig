//! Package-owned deep tests exposed only to the repository verification root.

test {
    _ = @import("fri/tests.zig");
    _ = @import("fields/tests/m31.zig");
    _ = @import("pcs/quotients/tests.zig");
}
