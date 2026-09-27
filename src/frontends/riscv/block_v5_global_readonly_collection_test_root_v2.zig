//! Cohesive first-pass counter/transport/roster gates plus real CPU callback codegen.
//! Test bodies do not run guests, PCS, STARKs, segments or devices.
const std = @import("std");
test {
    _ = @import("prover/block_v5_readonly_input_global_collection_test_v2.zig");
    _ = @import("prover/block_v5_readonly_input_collection_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_collection_bodies_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_provider_test_v2.zig");
    _ = @import("prover/block_v5_readonly_input_provider_bodies_test_v2.zig");
}
test "global readonly collection: real CPU driver CLI and callbacks retained" {
    @setEvalBranchQuota(1_000_000);
    std.mem.doNotOptimizeAway(&@import("ethereum_block_v5_cpu_produce.zig").main);
}
