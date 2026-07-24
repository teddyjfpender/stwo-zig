//! Native AIR constraint kernels admitted into the resident CUDA product.

pub const constant_qm31 = @import("constant_qm31.zig");
pub const wide_fibonacci = @import("wide_fibonacci.zig");

test {
    _ = constant_qm31;
    _ = wide_fibonacci;
}
