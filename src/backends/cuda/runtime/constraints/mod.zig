//! Native AIR constraint kernels admitted into the resident CUDA product.

pub const wide_fibonacci = @import("wide_fibonacci.zig");

test {
    _ = wide_fibonacci;
}
