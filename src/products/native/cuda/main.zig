//! Installed entry point for the focused Native CUDA product.

pub const stwo = @import("stwo_native_cuda");

pub fn main() !void {
    return @import("app.zig").main();
}
