test {
    _ = @import("prover/block_v5_witness_columns_store_test.zig");
    _ = @import("prover/block_v5_native_columns_stage_test.zig");
    _ = @import("prover/block_v5_cpu_staged_execution_source_test.zig");
}

test "staged witness driver compiles without starting segment proofs" {
    @import("std").mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_driver_v1.zig").run);
}
