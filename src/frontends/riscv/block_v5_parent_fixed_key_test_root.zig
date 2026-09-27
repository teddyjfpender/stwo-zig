test {
    _ = @import("prover/block_v5_parent_fixed_key_test_v1.zig");
}
test "parent fixed key: installed original and fixed-only CPU key bodies retained without commitment invocation" {
    const std = @import("std");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Parent = @import("recursion/blake3_execution_parent_proof.zig").ForBackend(Cpu);
    inline for (.{ &Parent.deriveKey, &Parent.deriveKeyWithProfile, &Parent.deriveKeyWithProfileAndPool, &Parent.deriveKeyFromFixed }) |body| std.mem.doNotOptimizeAway(body);
}
