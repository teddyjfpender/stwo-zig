const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Joint = @import("prover/block_v7_window_memory_joint_v1.zig");
const Impl = Joint.For(Cpu);
fn prepareUnionWindow(stage: *const Impl.Stage, epoch: @import("prover/block_v7_execution_epoch_v1.zig").Epoch, entries: []const @import("prover/block_v7_execution_epoch_v1.zig").Entry) !*@import("prover/block_v7_complete_union_memory_v1.zig").ForMode(true).Context {
    return @import("prover/block_v7_complete_union_memory_v1.zig").ForMode(true).prepare(Cpu, stage, epoch, entries);
}
test "window memory joint producer and independent verifier instantiate" {
    inline for (.{ &Impl.Stage.init, &Impl.Stage.prove, &Impl.Stage.entry, &Impl.Stage.deinit, &Impl.requireFixedRoot, &Impl.verify, &Impl.verifyAndCapture }) |function| std.mem.doNotOptimizeAway(function);
}
test "window memory union producer retains original state delta and nonhalt context" {
    std.mem.doNotOptimizeAway(&prepareUnionWindow);
}
