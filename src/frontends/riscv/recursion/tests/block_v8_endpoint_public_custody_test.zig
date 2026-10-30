const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Public = @import("../block_v8_endpoint_public_v1.zig");
const Bus = @import("../block_v8_endpoint_parent_protocol_v1.zig").Bus;
test "endpoint public reads preserve complete admission checks and selected field custody" {
    var words: [7 * 8]u32 = @splat(0);
    var felts = [_]Q{Q.one()};
    var operands = [_]Q{ Q.one(), Q.zero() };
    const child = Public.Values{ .allocator = std.testing.allocator, .template = @splat(7), .statement = .{ .allocator = std.testing.allocator, .words = &words, .felts = &felts, .first = &.{}, .claims = &.{}, .sealed_offset = 0, .roots_offset = .{ 0, 8, 16 } }, .public = &operands, .roots_count = 7 };
    const values = Bus.Values{ .children = &.{child} };
    const expected = [_]Bus.Expected{.{ .profile = @splat(7), .epoch = @splat(0), .root_count = 7 }};
    try values.requireRoster(&expected);
    var wire = Bus.Wire{ .circuit = 1500, .wire = 0, .uses = 1, .source = .public_input, .coordinate = 0 };
    try std.testing.expectEqualDeep(Q.one().toM31Array(), try values.at(wire));
    operands[1] = Q.fromM31Array(.{ .{ .v = core.fields.m31.Modulus }, M.zero(), M.zero(), M.zero() });
    try std.testing.expectError(error.InvalidFusedRecursivePublicInputs, values.requireRoster(&expected));
    // Per-row reading is deliberately local; full vector validation belongs
    // to admission. This catches regressions to a scan for every operand.
    try std.testing.expectEqualDeep(Q.one().toM31Array(), try values.at(wire));
    wire.coordinate = 1;
    try std.testing.expectError(error.InvalidEndpointParentOperand, values.at(wire));
    wire.coordinate = 2;
    try std.testing.expectError(error.InvalidEndpointParentOperand, values.at(wire));
    operands[1] = Q.zero();
    felts[0] = Q.fromM31Array(.{ M.zero(), .{ .v = core.fields.m31.Modulus }, M.zero(), M.zero() });
    wire.source = .felt_word;
    wire.coordinate = 0;
    try std.testing.expectError(error.InvalidEndpointParentOperand, values.at(wire));
    try std.testing.expectError(error.InvalidFusedRecursivePublicInputs, values.requireRoster(&expected));
    felts[0] = Q.one();
    try values.requireRoster(&expected);
    wire.coordinate = 4;
    try std.testing.expectError(error.InvalidEndpointParentOperand, values.at(wire));
    const empty = Bus.Values{ .children = &.{} };
    try std.testing.expectError(error.InvalidEndpointParentRoster, empty.at(wire));
}
