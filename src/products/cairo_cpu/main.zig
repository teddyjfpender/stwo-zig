//! Installed entry point for the focused Cairo CPU/SIMD product.

pub const stwo = @import("stwo_cairo_cpu");

pub fn main() !void {
    return @import("app.zig").main();
}
