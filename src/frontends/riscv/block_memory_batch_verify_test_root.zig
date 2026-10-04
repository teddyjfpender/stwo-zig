comptime {
    _ = @import("prover/block_memory_batch_verify_v2.zig");
    _ = @import("prover/block_memory_complete_receiver_v3.zig");
    _ = @import("prover/tests/block_memory_complete_receiver_v3_test.zig");
    _ = @import("prover/tests/block_memory_batch_statement_v2_test.zig");
    _ = @import("prover/tests/block_memory_batch_verify_proof_test.zig");
}
