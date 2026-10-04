test {
    _ = @import("prover/tests/block_v5_initial_source_test.zig");
    _ = @import("prover/tests/block_v5_memory_batch_test.zig");
    _ = @import("prover/tests/block_v5_memory_replay_adapter_test.zig");
    _ = @import("prover/block_memory_shared_instance_proof_v2.zig");
}
