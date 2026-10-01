//! The resident CUDA circuit product links proof conversion, not the CPU
//! circuit prover. Fail if CPU composition is invoked through an imported API.
const cairo = @import("stwo_cairo_frontend");

pub fn executor() cairo.proving.air.native_evaluator.Executor {
    return .{ .resolve = forbidden };
}

fn forbidden(_: [32]u8) ?cairo.proving.air.native_evaluator.Kernel {
    @panic("CPU circuit composition is forbidden in the resident CUDA product");
}
