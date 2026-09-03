//! Focused nonproduction candidate-provider transcript and d5 adapter gate.

const std = @import("std");
const candidate_protocol = @import(
    "prover/memory_provider_shards/ethereum_candidate_omit_protocol_v1.zig",
);
const degree5_candidate = @import(
    "prover/memory_provider_shards/degree5_ethereum_candidate_provider_v1.zig",
);

comptime {
    _ = @import("air/lang/typed_poseidon2_degree5_backend_test.zig");
    _ = @import(
        "prover/memory_provider_shards/degree5_provider_stage_a_transaction_v1_test.zig",
    );
}

test "candidate provider transcript and degree-five adapter declarations compile" {
    std.testing.refAllDecls(candidate_protocol);
    std.testing.refAllDecls(degree5_candidate);
    try std.testing.expect(!candidate_protocol.production_active);
    try std.testing.expect(!degree5_candidate.production_active);
}
