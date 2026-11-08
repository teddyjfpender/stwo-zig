//! Installed Stwo Zig production proof command.

pub const stwo = @import("stwo");

pub fn main() !void {
    return @import("app.zig").main();
}
