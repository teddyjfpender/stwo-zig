comptime {
    _ = @import(
        "ethereum_incremental_full_leaf_prepared_proof_transaction_v4_test.zig",
    );
    _ = @import(
        "ethereum_incremental_full_leaf_throughput_execution_v1_test.zig",
    );
    _ = @import(
        "ethereum_incremental_prepared_program_commitment_v1_test.zig",
    );
}
