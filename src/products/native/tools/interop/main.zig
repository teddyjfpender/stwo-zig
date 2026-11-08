//! Installed interop command-line entry point.

pub const stwo = @import("stwo");

pub fn main() !void {
    return @import("app.zig").main();
}
