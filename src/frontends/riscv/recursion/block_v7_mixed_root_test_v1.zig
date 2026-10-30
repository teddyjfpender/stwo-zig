const std = @import("std");
const B = @import("block_v7_mixed_public_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
test "v7 mixed canonical reconstruction and global closure codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_inputs_v1.zig").Owned.init);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_inputs_v1.zig").Owned.requireSame);
    std.mem.doNotOptimizeAway(&@import("../prover/block_v7_global_public_closure_v1.zig").closePublic);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_protocol_v1.zig").Admission.init);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_preparation_v1.zig").prepareDraining);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_fixed_v1.zig").Owned.derive);
}
test "v7 mixed roster pins family order epoch and original entry" {
    const native = try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)});
    const program = try E.Entry.init(.program, 0, @splat(3), &.{ @splat(4), @splat(5) });
    var expected = [_]B.Expected{ .{ .kind = .native, .index = 0, .template = @splat(6), .epoch = @splat(7), .entry = native }, .{ .kind = .program, .index = 0, .template = @splat(8), .epoch = @splat(7), .entry = program } };
    const digest = try B.rosterDigest(&expected);
    expected[1].entry.roots[0][0] ^= 1;
    try std.testing.expect(!std.meta.eql(digest, try B.rosterDigest(&expected)));
    expected[1].epoch[0] ^= 1;
    try std.testing.expectError(error.MixedV7Epochs, B.rosterDigest(&expected));
    expected[1].epoch[0] ^= 1;
    try std.testing.expectError(error.InvalidV7MixedRoster, B.rosterDigest(&.{ expected[1], expected[0] }));
    try std.testing.expectError(error.InvalidV7MixedRoster, B.rosterDigest(&.{ expected[0], expected[0] }));
    expected[1].kind = .lookup;
    try std.testing.expectError(error.InvalidV7MixedRoster, B.rosterDigest(&expected));
}
