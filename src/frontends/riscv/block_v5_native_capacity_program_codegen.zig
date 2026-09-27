//! Actual producer-independent program/provider fresh closure bodies only.
//! This object has no runtime entrypoint and does not prove or load files.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
export fn stwo_capacity_program_closure_body_gate() void {
    const Capacity = @import("prover/block_v5_program_native_capacity_batch_receiver_v1.zig").ForBackend(Cpu);
    const Legacy = @import("prover/block_v5_program_native_batch_receiver_v3.zig").ForBackend(Cpu);
    std.mem.doNotOptimizeAway(&Capacity.verifyWithCompositeHooks);
    std.mem.doNotOptimizeAway(&Legacy.verifyWithCompositeHooks);
}
