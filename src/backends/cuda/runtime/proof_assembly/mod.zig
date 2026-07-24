//! Mechanical decoding of the single resident proof output.

pub const decommit_bundle = @import("decommit_bundle.zig");
pub const stark_bundle = @import("stark_bundle.zig");

test {
    _ = decommit_bundle;
    _ = stark_bundle;
}
