//! Build entry for sha/tests/sha_joint_prover_test.zig.
const selected = @import("src/sha/tests/sha_joint_prover_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
