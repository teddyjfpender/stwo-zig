const std = @import("std");
const direct = @import("materialization_cost_direct.zig");

test "late root folds extend an already-interned node lifetime" {
    var arena = direct.Arena.init(std.testing.allocator);
    defer arena.deinit();

    const early = try arena.intern(.{ .op = .constant, .value = 1 });
    _ = try arena.intern(.{ .op = .constant, .value = 2 });
    const roots = [_]direct.RootUse{try arena.recordRoot(early)};

    try std.testing.expectEqual(@as(u64, 2), try arena.peakLiveNodes(
        std.testing.allocator,
        &roots,
    ));
}

test "root folding rejects values outside the canonical DAG" {
    var arena = direct.Arena.init(std.testing.allocator);
    defer arena.deinit();

    _ = try arena.intern(.{ .op = .constant, .value = 1 });
    try std.testing.expectError(error.CountOverflow, arena.recordRoot(1));
}
