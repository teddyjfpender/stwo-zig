const std = @import("std");
const scalar = @import("scalar_wire_source.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
test "Scalar wire sources pin base-field tuple shape and fixed identities" {
    const a = std.testing.allocator;
    const digest = try scalar.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &scalar.SEMANTIC_DIGEST)) std.debug.print("SCALAR_WIRE_DIGEST={x}\n", .{digest});
    try std.testing.expectEqualSlices(u8, &scalar.SEMANTIC_DIGEST, &digest);
    var definition = try scalar.build(a);
    defer definition.deinit();
    const plan = try @import("universal_relation_binding.zig").Binding(scalar).authenticate(&definition);
    for ([_]u32{ 0, 1, core.fields.m31.Modulus - 1 }) |value| {
        const row = try scalar.logicalRow(1502, 17, 3, M31.fromCanonical(value));
        const entry = plan.preparedEntries(row)[0];
        const expected = [_]u32{ 1502, 17, value, 0, 0, 0 };
        for (entry.values[0..6], expected) |actual, word| try std.testing.expectEqual(word, (try actual.tryIntoM31()).v);
        try std.testing.expectEqual(@as(u32, 3), (try entry.numerator.tryIntoM31()).v);
    }
    const routed = try scalar.routedRow(1502, 17, 3, 1900, 9, M31.fromCanonical(42));
    const consumer = plan.preparedEntries(routed)[1];
    const expected_source = [_]u32{ 1900, 9, 42, 0, 0, 0 };
    for (consumer.values[0..6], expected_source) |actual, word| try std.testing.expectEqual(word, (try actual.tryIntoM31()).v);
    try std.testing.expectEqual(core.fields.m31.Modulus - 1, (try consumer.numerator.tryIntoM31()).v);
    try std.testing.expectError(error.InvalidScalarWireSource, scalar.routedRow(1, 2, 3, 1, 2, M31.zero()));
    try std.testing.expect(plan.preparedEntries(@splat(M31.zero()))[0].numerator.isZero());
    try std.testing.expectError(error.InvalidScalarWireSource, scalar.logicalRow(0, 0, 1, .{ .v = core.fields.m31.Modulus }));
    try std.testing.expectError(error.InvalidScalarWireSource, scalar.logicalRow(core.fields.m31.Modulus, 0, 1, M31.zero()));
}
