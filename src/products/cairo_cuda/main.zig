//! Installed entry point for the focused Cairo CUDA product.

pub const stwo = @import("stwo_cairo_cuda");

pub fn main() !void {
    return @import("app.zig").main();
}

// Import the product module explicitly so focused build filters discover
// its contract tests rather than silently running an empty test binary.
test {
    _ = stwo;
    _ = @import("app.zig");
}
