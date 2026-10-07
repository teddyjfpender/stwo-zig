//! Build entry for runtime/showcase.zig.
const selected = @import("src/runtime/showcase.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
