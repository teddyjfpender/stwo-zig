//! Focused machine-readable benchmark entry point.

const stwo = @import("stwo_native_cpu");
const runner = @import("native_proof_runner");
const identity = @import("identity.zig");

pub fn main() !void {
    return runner.mainWithProduct(
        stwo.examples.wide_fibonacci.CpuProverEngine,
        .cpu_native,
        identity.value(),
    );
}
