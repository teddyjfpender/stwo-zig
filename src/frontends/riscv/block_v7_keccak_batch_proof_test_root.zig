const std = @import("std");
test {
    std.testing.refAllDeclsRecursive(@import("prover/block_v7_keccak_batch_proof_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend));
}

test {
    std.testing.refAllDecls(@import("prover/tests/block_v7_keccak_batch_execution_test.zig"));
}
