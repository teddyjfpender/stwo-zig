//! Generic prover unit and integration tests.

test {
    _ = @import("fri.zig");
    _ = @import("poly/circle_transforms.zig");
    _ = @import("pcs/mod.zig");
    _ = @import("../vcs/tests/mod.zig");
    _ = @import("../vcs_lifted/tests/mod.zig");
}
