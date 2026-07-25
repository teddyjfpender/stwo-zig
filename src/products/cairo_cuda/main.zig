//! Installed entry point for the focused Cairo CUDA product.

pub const stwo = @import("stwo_cairo_cuda");

pub fn main() !void {
    return @import("app.zig").main();
}
