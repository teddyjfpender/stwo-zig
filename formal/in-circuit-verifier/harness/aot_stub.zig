//! Stand-in for the build-generated `circuit_composition_cpu_aot` module.
//!
//! The real module compiles the circuit AIR's captured programs into C
//! kernels; its `executor()` resolves a program hash to a kernel. The
//! harness never proves on the native-kernel fast path, so this stub
//! resolves nothing and every program falls back to the SIMD interpreter
//! (same field arithmetic, same proof bytes — see
//! `src/integrations/circuit_cpu/composition_aot_build.zig`).

const cairo = @import("stwo_cairo_frontend");
const native = cairo.proving.air.native_evaluator;

pub fn executor() native.Executor {
    return .{ .resolve = resolve };
}

fn resolve(_: [32]u8) ?native.Kernel {
    return null;
}
