//! Focused root for the `STWIOL01` omitted-leaf envelope.
//!
//! It carries the unit gates plus a `refAllDecls` of the codec itself, so a
//! declaration only the (engine-generic) encoder or decoder would instantiate
//! is still analysed here rather than in a ten-minute product build.

const std = @import("std");

const envelope =
    @import("ethereum_incremental_omitted_leaf_proof_artifact_v1.zig");

comptime {
    _ = @import("ethereum_incremental_omitted_leaf_proof_artifact_v1_test.zig");
}

test "STWIOL01 envelope declarations compile" {
    std.testing.refAllDecls(envelope);
    std.testing.refAllDecls(envelope.OmissionSectionV1);
    std.testing.refAllDecls(envelope.OmissionPinsV1);
    std.testing.refAllDecls(envelope.OmissionShardRecordV1);
}
