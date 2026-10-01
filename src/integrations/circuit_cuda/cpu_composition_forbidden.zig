//! The resident CUDA benchmark links circuit proof conversion, not the CPU
//! circuit prover. Fail if that prover is invoked through an imported API.
const cairo = @import("stwo_cairo_frontend");

pub fn executor() cairo.proving.air.native_evaluator.Executor {
    @panic("CPU circuit composition is forbidden in the resident CUDA benchmark");
}
