const std = @import("std");
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const Prepare = @import("block_v6_mixed_direct_prepare_v1.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
test "mixed direct roster and schedule reject ambiguity" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidMixedDirectCount, Prepare.prepareDraining(a, &.{}, &.{}));
    const one = Bus.Expected{ .native = .{ .index = 0, .template = @splat(1) } };
    const two = Bus.Expected{ .native = .{ .index = 1, .template = @splat(2) } };
    const id = try Bus.rosterDigest(&.{ one, two });
    try std.testing.expectError(error.InvalidMixedDirectRoster, Bus.rosterDigest(&.{ one, one }));
    try std.testing.expectError(error.InvalidMixedDirectRoster, Bus.rosterDigest(&.{ two, one }));
    var changed = two;
    changed.native.template[0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, try Bus.rosterDigest(&.{ one, changed })));
    const native = Bus.Wire{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .source = .{ .native = .word }, .coordinate = 0 };
    const auxiliary = Bus.Wire{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .source = .{ .auxiliary = .{ .source_raw = .word } }, .coordinate = 0 };
    try std.testing.expect(!std.meta.eql(try Bus.scheduleDigest(&.{native}), try Bus.scheduleDigest(&.{auxiliary})));
    try std.testing.expectError(error.InvalidMixedDirectSchedule, Bus.scheduleDigest(&.{ native, native }));
    var wrong_child = native;
    wrong_child.child = Bus.MAX_CHILDREN;
    try std.testing.expectError(error.InvalidMixedDirectSchedule, Bus.scheduleDigest(&.{wrong_child}));
    try std.testing.expect(Protocol.VERSION == 1);
}
