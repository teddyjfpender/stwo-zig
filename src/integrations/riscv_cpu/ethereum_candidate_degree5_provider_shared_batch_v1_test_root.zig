//! Focused root for the shared-transcript D5 provider batch.
//!
//! It carries the unit gates plus a `refAllDecls` of the module itself, so a
//! declaration only the (engine-generic) prover would instantiate is still
//! analysed here rather than in a ten-minute product build.

const std = @import("std");

const shared_batch =
    @import("ethereum_candidate_degree5_provider_shared_batch_v1.zig");

comptime {
    _ = @import("ethereum_candidate_degree5_provider_shared_batch_v1_test.zig");
}

test "shared D5 provider batch declarations compile" {
    std.testing.refAllDecls(shared_batch);
}
