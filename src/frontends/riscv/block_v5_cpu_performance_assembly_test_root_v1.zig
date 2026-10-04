//! Cohesive CPU metadata/ownership/transport checks and real production bodies.
//! No guest, PCS commitment, STARK, segment, forest or device run is invoked.
const std = @import("std");
test {
    _ = @import("prover/block_v5_supplemental_worker_reuse_test_v1.zig");
    _ = @import("prover/tests/block_v5_native_recursive_consuming_test.zig");
    _ = @import("prover/block_v5_supplemental_recursive_lifetime_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_collection_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_collection_bodies_test_v1.zig");
    _ = @import("prover/block_v5_cpu_capacity_driver_test_v1.zig");
    _ = @import("prover/blake3_scoped_parent_admission_test_v1.zig");
}
test "cpu performance assembly: genuine cache publication driver receiver and canonical CLI bodies retained" {
    @setEvalBranchQuota(1_000_000);
    @import("block_v5_word_expected_setup_codegen_v1.zig").stwo_word_expected_setup_body_gate();
    @import("block_v5_supplemental_recursive_lifetime_codegen_v1.zig").stwo_supplemental_recursive_lifetime_body_gate();
    @import("block_v5_scoped_parent_admission_isolated_codegen_v1.zig").stwo_scoped_parent_admission_isolated_body_gate();
    std.mem.doNotOptimizeAway(&@import("ethereum_block_v5_cpu_produce.zig").main);
}
