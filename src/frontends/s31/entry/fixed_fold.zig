//! Build entry for recursion/fixed_fold.zig.
const selected = @import("src/recursion/fixed_fold.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
