//! Build entry for runtime/verifier_main.zig.
const selected = @import("src/runtime/verifier_main.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
