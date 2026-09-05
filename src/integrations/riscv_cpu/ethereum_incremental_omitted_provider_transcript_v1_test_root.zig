//! Focused root for the V4 omitted-provider shard transcript source.
//!
//! It carries the unit gates plus a `refAllDecls` of the module itself, so a
//! declaration that only the (engine-generic) shard prover would instantiate
//! is still analysed here rather than in a ten-minute product build.

const std = @import("std");

const transcript =
    @import("ethereum_incremental_omitted_provider_transcript_v1.zig");

comptime {
    _ = @import("ethereum_incremental_omitted_provider_transcript_v1_test.zig");
}

test "omitted provider transcript v1 declarations compile" {
    std.testing.refAllDecls(transcript);
}
