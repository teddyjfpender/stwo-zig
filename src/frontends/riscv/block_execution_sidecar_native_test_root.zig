comptime {
    _ = @import("prover/block_execution_sidecar_native_test.zig");
    _ = @import("prover/block_execution_sidecar_batch_v2.zig");
    _ = @import("recursion/blake3_block_execution_span_v3.zig");
    _ = @import("prover/block_execution_range_shard_v2.zig");
    _ = @import("prover/block_execution_range_table_v2.zig");
    _ = @import("prover/block_execution_batch_receiver_v2.zig");
    _ = @import("prover/block_execution_sha_receiver_test.zig");
    _ = @import("prover/blake3_commitment_plan.zig");
    _ = @import("prover/block_execution_external_access_bridge_v2.zig");
    _ = @import("prover/block_execution_external_trace_v2.zig");
    _ = @import("prover/block_execution_external_domain_v2.zig");
    _ = @import("prover/block_execution_external_batch_v2.zig");
    _ = @import("prover/block_execution_external_trace_test.zig");
    _ = @import("prover/block_execution_external_proof_test.zig");
}
