//! Focused CPU checkpoint qualification. No full block or recursive gate.
test {
    _ = @import("prover/tests/block_v6_ram_commitment_store_test.zig");
    _ = @import("prover/tests/block_v6_lookup_commitment_store_test.zig");
    _ = @import("prover/tests/block_v5_caller_columns_stage_test.zig");
}
