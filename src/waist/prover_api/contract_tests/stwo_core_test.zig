//! PCS request parameters exposed in the prover transaction signatures.
const std = @import("std");
const core = @import("stwo_core");

test "cdc: prover API FRI request preserves query geometry and rejects invalid bounds" {
    const F = core.fri.FriConfig;
    const config = try F.init(2, 3, 17);
    try std.testing.expectEqual(@as(usize, 32), config.lastLayerDomainSize());
    try std.testing.expectEqual(@as(u32, 51), config.securityBits());
    try std.testing.expectEqual(@as(usize, 17), config.n_queries);
    try std.testing.expectError(error.InvalidBlowupFactor, F.init(2, 0, 17));
    try std.testing.expectError(error.InvalidLastLayerDegreeBound, F.init(11, 3, 17));
}
