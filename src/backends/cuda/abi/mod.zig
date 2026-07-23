//! Narrow, exact C ABI modules for the resident CUDA product.

pub const runtime = @import("runtime.zig");
pub const types = @import("types.zig");

test {
    _ = runtime;
    _ = types;
}
