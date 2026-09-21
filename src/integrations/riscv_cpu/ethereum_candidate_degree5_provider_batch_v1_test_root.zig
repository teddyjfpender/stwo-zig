//! Focused structural gate for the runtime-authorized D5 provider batch.

const std = @import("std");

const prepared =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
const proof =
    @import("ethereum_candidate_degree5_provider_proof_batch_v1.zig");

comptime {
    _ = @import("ethereum_candidate_degree5_provider_batch_execution_v1_test.zig");
}

test "candidate D5 prepared and proof batch declarations compile" {
    std.testing.refAllDecls(prepared);
    std.testing.refAllDecls(proof);
}
