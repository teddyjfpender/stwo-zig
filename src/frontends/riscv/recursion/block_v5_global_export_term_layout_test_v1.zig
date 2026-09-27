//! Pure transcript geometry, never an admitted policy, capture or proof.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.Modulus;

test "global export layout: exact original sequential transcript matches all direct window coordinates" {
    const terms = [_]Q{ Q.zero(), Q.one(), Q.fromU32Unchecked(1, 2, 3, 4) };
    for ([_]u32{ 0, 1, 3, 64, 4096 }) |windows| {
        var original = Bus.Counter{};
        original.mixU32s(&.{ 1, 2, 3 });
        original.mixU32s(&.{}); // Empty invocations retain a real frame.
        original.mixRoot(@splat(4));
        original.mixU64(0xffffffff12345678);
        original.mixFelts(&.{ Q.one(), Q.zero() });
        const layout = try Bus.ExportLayout.fromCounter(original, windows);
        for (0..windows) |index| {
            const direct = try layout.at(@intCast(index));
            for (direct, 0..) |cell, kind| {
                const expected = Bus.ExportCell{ .window = @intCast(index), .kind = @enumFromInt(kind), .frame = original.frames, .index = @intCast(kind), .first_cell = original.cells + @as(u32, @intCast(4 * kind)) };
                try std.testing.expectEqualDeep(expected, cell);
            }
            original.mixFelts(&terms);
            if (original.failure) |failure| return failure;
        }
        try std.testing.expectError(error.InvalidGlobalPublicSchedule, layout.at(windows));
    }
}

test "global export layout: modulus frame cell limits and high window indices preserve original rejection" {
    var original = Bus.Counter{ .frames = 123, .cells = M - 25 };
    const layout = try Bus.ExportLayout.fromCounter(original, 4);
    try std.testing.expectEqual(M - 25, (try layout.at(0))[0].first_cell);
    try std.testing.expectEqual(M - 13, (try layout.at(1))[0].first_cell);
    try std.testing.expectError(error.GlobalPublicExportResourceLimit, layout.at(2));
    const terms = [_]Q{ Q.zero(), Q.zero(), Q.zero() };
    original.mixFelts(&terms);
    original.mixFelts(&terms);
    original.mixFelts(&terms);
    try std.testing.expectEqual(error.GlobalPublicExportResourceLimit, original.failure.?);
    const frame_layout = try Bus.ExportLayout.fromCounter(.{ .frames = M - 1, .cells = 100 }, 2);
    try std.testing.expectEqual(M - 1, (try frame_layout.at(0))[0].frame);
    try std.testing.expectError(error.GlobalPublicExportResourceLimit, frame_layout.at(1));
    const large = try Bus.ExportLayout.fromCounter(.{}, std.math.maxInt(u32));
    try std.testing.expectError(error.GlobalPublicExportResourceLimit, large.at(std.math.maxInt(u32) - 1));
    try std.testing.expectError(error.GlobalPublicExportResourceLimit, Bus.ExportLayout.fromCounter(.{ .cells = M }, 1));
    try std.testing.expectError(error.GlobalPublicExportResourceLimit, Bus.ExportLayout.fromCounter(.{ .frames = M }, 1));
    try std.testing.expectError(error.Overflow, Bus.ExportLayout.fromCounter(.{ .failure = error.Overflow }, 1));
}
