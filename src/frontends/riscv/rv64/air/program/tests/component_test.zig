const std = @import("std");
const core = @import("stwo_core");
const C = @import("../component.zig");
const provider = @import("../provider.zig");
const rom = @import("../setup.zig");
const a = std.testing.allocator;
const Q = core.fields.qm31.QM31;

test "rv64 program provider: concrete adapters own local geometry in shared trees" {
    const component = C.Component{ .log_size = 5, .fixed_offset = 7, .main_offset = 11, .interaction_offset = 13, .challenges = .{ .offset = Q.one(), .coefficients = @splat(Q.one()) }, .claim = Q.zero() };
    _ = component.asProverComponent();
    _ = component.asVerifierComponent();
    var bounds = try component.traceLogDegreeBounds(a);
    defer {
        for (bounds.items) |tree| a.free(tree);
        bounds.deinit(a);
    }
    const indices = try component.preprocessedColumnIndices(a);
    defer a.free(indices);
    try std.testing.expectEqual(@as(usize, 7), indices[0]);
    try std.testing.expectEqual(@as(usize, C.FIXED + 6), indices[indices.len - 1]);
    const point = core.circle.CirclePointQM31{ .x = Q.fromU32Unchecked(2, 3, 4, 5), .y = Q.fromU32Unchecked(6, 7, 8, 9) };
    var masks = try component.maskPoints(a, point, 12);
    defer {
        for (masks.items) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        }
        masks.deinit(a);
    }
    try std.testing.expectEqual(@as(usize, C.FIXED), masks.items[0].len);
    try std.testing.expectEqual(@as(usize, 2), masks.items[2][4].len);
    try std.testing.expectEqual(@as(usize, 1), masks.items[2][0].len);
    try std.testing.expectError(error.InvalidRv64MaskGeometry, component.maskPoints(a, point, 4));
    var setup = try rom.Setup.init(a, .{ .base = 0x100001000, .words = &.{0x00108093} });
    defer setup.deinit();
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    const n = setup.domainSize();
    try std.testing.expect(fixed[rom.field.COUNT * n + provider.physical(0, setup.log_size)].eql(core.fields.m31.M31.one()));
    try std.testing.expect(fixed[(rom.field.COUNT + 1) * n + provider.physical(n - 1, setup.log_size)].eql(core.fields.m31.M31.one()));
}
