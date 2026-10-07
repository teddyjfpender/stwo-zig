//! Build entry for runtime/mvp_runtime.zig.
const selected = @import("src/runtime/mvp_runtime.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
