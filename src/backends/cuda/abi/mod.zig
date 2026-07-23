//! Narrow, exact C ABI modules for the resident CUDA product.

pub const aot = @import("aot.zig");
pub const runtime = @import("runtime.zig");
pub const types = @import("types.zig");

test {
    _ = aot;
    _ = runtime;
    _ = types;
}
