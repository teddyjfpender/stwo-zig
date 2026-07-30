//! Package-owned Metal backend tests not exported by the public API.

test {
    _ = @import("tests/command_epoch.zig");
    _ = @import("tests/fri_fold_commit.zig");
    _ = @import("tests/polynomial_eval.zig");
}
