//! Build entry for runtime/mvp_verifier_main.zig.
const selected = @import("src/runtime/mvp_verifier_main.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
