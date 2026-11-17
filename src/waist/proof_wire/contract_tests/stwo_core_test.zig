//! Core config admission used by proof-wire reconstruction.
const std = @import("std");
const core = @import("stwo_core");

test "cdc: proof wire config keeps fold schedule and refuses zero fold step" {
    const F = core.pcs.config_v2.FriConfigV2;
    const config = try F.init(26, 0, 1, 70, 4);
    const folding = config.folding();
    try std.testing.expectEqual(@as(u32, 4), folding.fold_step);
    try std.testing.expectEqual(@as(usize, 70), folding.n_queries);
    try std.testing.expectEqual(@as(u32, 96), config.securityBits());
    try std.testing.expectError(error.InvalidFoldStep, F.init(26, 0, 1, 70, 0));
    try std.testing.expectError(error.InvalidBlowupFactor, F.init(26, 0, 0, 70, 4));
}
