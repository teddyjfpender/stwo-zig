//! CPU/SIMD execution of backend-neutral Cairo AIR programs.

pub const component = @import("component.zig");
pub const simd_evaluator = @import("simd_evaluator.zig");

test {
    _ = component;
    _ = simd_evaluator;
}
