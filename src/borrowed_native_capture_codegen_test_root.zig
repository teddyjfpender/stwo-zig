//! Actual callback body retention only; no proof or segment is invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
test "borrowed proof capture actual native and leaf callback bodies codegen" {
    const Native = @import("frontends/riscv/prover/block_v5_native_execution_proof_v3.zig").ForBackend(Cpu);
    std.mem.doNotOptimizeAway(&Native.verifyCaptureBorrowedWithCatalog);
    const Leaf = @import("frontends/riscv/prover/block_v5_native_recursive_leaf_stage_v1.zig").ForBackend(Cpu);
    var stage: Leaf = undefined;
    const hooks = stage.hooks();
    std.mem.doNotOptimizeAway(hooks.on_proof.?);
}
