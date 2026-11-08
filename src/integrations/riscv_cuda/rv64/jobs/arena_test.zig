const std = @import("std");
const Arena = @import("arena.zig").Arena;

test "arena refuses overflowing sizes without changing allocation state" {
    var arena = Arena{ .base = 0x10000, .words = 1024 };
    try std.testing.expectError(error.ResourceSizeOverflow, arena.stageAlloc(.bottom, std.math.maxInt(usize)));
    try std.testing.expectEqual([2]usize{ 0, 0 }, arena.staged);
    arena.beginWork(.bottom, false);
    const before = try arena.workAlloc(64);
    try std.testing.expectError(error.ResourceSizeOverflow, arena.workAlloc(std.math.maxInt(usize)));
    arena.workFree(before, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 64), arena.bump);
    try std.testing.expectEqual(@as(usize, 64), arena.live);
}

test "arena: staged inputs sit at their side's end and bound the other side's work" {
    var a = Arena{ .base = 0x10000, .words = 1024 };
    a.beginStage(.bottom);
    const b0 = try a.stageAlloc(.bottom, 10); // rounds to 64
    try std.testing.expectEqual(@as(usize, 0x10000), b0);
    a.beginStage(.top);
    const t0 = try a.stageAlloc(.top, 64);
    try std.testing.expectEqual(@as(usize, 0x10000 + 4 * (1024 - 64)), t0);
    // bottom job works between its inputs and the staged top inputs
    a.beginWork(.bottom, true);
    const w0 = try a.workAlloc(128);
    try std.testing.expectEqual(@as(usize, 0x10000 + 4 * 64), w0);
    try std.testing.expectError(error.JobWorkExceedsArena, a.workAlloc(1024 - 64 - 128 - 64 + 1));
    _ = try a.workAlloc(1024 - 64 - 128 - 64);
    try std.testing.expectEqual(@as(usize, 1024 - 64), a.peak);
}

test "arena: top side grows down; LIFO free reclaims; no staged neighbour frees the window" {
    var a = Arena{ .base = 0, .words = 640 };
    a.beginStage(.top);
    _ = try a.stageAlloc(.top, 64);
    a.beginWork(.top, false); // nothing staged on the bottom: whole window
    const x = try a.workAlloc(64);
    try std.testing.expectEqual(@as(usize, 4 * (640 - 128)), x);
    const y = try a.workAlloc(100);
    a.workFree(y, 100);
    const z = try a.workAlloc(128);
    try std.testing.expectEqual(y, z);
    a.workFree(x, 64); // not the most recent: kept until the window resets
    try std.testing.expectEqual(z - 4 * 64, try a.workAlloc(1));
}

test "arena: staged inputs of both sides cannot exceed the arena" {
    var a = Arena{ .base = 0, .words = 256 };
    a.beginStage(.bottom);
    _ = try a.stageAlloc(.bottom, 128);
    a.beginStage(.top);
    _ = try a.stageAlloc(.top, 128);
    try std.testing.expectError(error.StagedInputsExceedArena, a.stageAlloc(.top, 1));
    a.beginStage(.bottom); // the bottom job finished; its inputs are reusable
    _ = try a.stageAlloc(.bottom, 64);
}
