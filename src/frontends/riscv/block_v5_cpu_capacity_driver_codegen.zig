//! Retain both real complete CPU driver bodies without invoking either one.
//! Codegen includes collection, staged PCS transfer, fused sidecar production,
//! native recursion, incremental exact forest and fresh detached all-family reception.
const std = @import("std");
const Runner = @import("prover/block_v4_cpu_runner_source.zig");
const Common = @import("prover/block_v5_cpu_driver_common_v1.zig");
const Planning = @import("prover/block_v5_cpu_driver_admission_v1.zig");
fn Bodies(comptime capacity: bool) type {
    return struct {
        const Driver = Common.ForCapacity(capacity);
        const Admission = Planning.ForCapacity(capacity);
        fn run(a: std.mem.Allocator, dir: std.fs.Dir, source: *Runner.Source, input: Admission.InputPolicy, options: Driver.Options) anyerror!Driver.Result {
            return Driver.run(a, dir, source, input, options);
        }
    };
}
pub export fn stwo_capacity_cpu_driver_body_gate() void {
    // Preserve the public legacy store adapter while both drivers use the
    // shared genuinely typed RAM callback kernel.
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_sorted_memory_replay_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).proveWithStore);
    inline for (.{ false, true }) |capacity| {
        const Driver = Common.ForCapacity(capacity);
        const Body = Bodies(capacity);
        inline for (.{ &Body.run, &Driver.Options.validate, &Driver.nativeMetadata, &Driver.externalRetirements }) |function| std.mem.doNotOptimizeAway(function);
    }
}
