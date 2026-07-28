//! Prover-side execution of backend-neutral Cairo AIR programs.

pub const component = @import("component.zig");
pub const device_stage = @import("device_stage.zig");
pub const simd_evaluator = @import("simd_evaluator.zig");

test {
    _ = component;
    _ = device_stage;
    _ = simd_evaluator;
}
