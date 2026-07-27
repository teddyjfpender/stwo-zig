//! Installed entry point for the focused Cairo Metal product.

pub const stwo = @import("stwo_cairo_metal");

pub fn main() !void {
    return @import("app.zig").main();
}
