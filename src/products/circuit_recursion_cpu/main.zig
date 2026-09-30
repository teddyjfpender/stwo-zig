//! Installed entry point of `stwo-circuit-recursion-cpu`.

pub fn main() !void {
    return @import("app.zig").main();
}

test {
    _ = @import("app.zig");
}
