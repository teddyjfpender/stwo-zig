//! Build entry for recursion/state_fold.zig.
const selected = @import("src/recursion/state_fold.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
