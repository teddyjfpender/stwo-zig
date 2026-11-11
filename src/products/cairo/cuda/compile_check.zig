//! Force semantic analysis of the complete product; no runtime is linked.
export fn stwo_cairo_cuda_compile_check() void {
    @import("app.zig").main() catch {};
}
