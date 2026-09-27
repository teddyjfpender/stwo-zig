const std = @import("std");
const core = @import("stwo_core");
const draw = @import("blake3_draw_witness.zig");
const M31 = core.fields.m31.M31;
fn statement() !draw.Statement {
    var channel = core.channel.blake3.Channel{};
    channel.mixU64(198);
    channel.n_draws = 3;
    const state = channel.digestBytes();
    const values = try channel.drawSecureFelts(std.testing.allocator, 2);
    defer std.testing.allocator.free(values);
    return .{ .namespace = 601, .state = state, .start = 3, .attempts = 1, .values = values[0].toM31Array() ++ values[1].toM31Array() };
}
test "BLAKE3 ordered draws match native outputs and independently rebuilt fixed columns" {
    const a = std.testing.allocator;
    const s = try statement();
    var live = try draw.prepare(a, s);
    defer live.deinit();
    var fixed = try draw.trusted(a, s);
    defer fixed.deinit();
    try std.testing.expectEqual(@as(u64, 4), live.next_draw);
    inline for (.{ draw.g, draw.xor, draw.boundary, draw.challenge }, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.challenge_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.challenge_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{s});
    try singleDraws(s);
}
test "BLAKE3 ordered draws reject skipped accepted attempts false outputs and counter wrap" {
    const a = std.testing.allocator;
    var s = try statement();
    // The first native draw accepts. Claiming a later final draw must not skip it.
    s.attempts = 2;
    var skipped = try draw.prepare(a, s);
    defer skipped.deinit();
    try std.testing.expect(skipped.challenge_rows[0][70].eql(M31.one()));
    try std.testing.expect(!try boundariesSatisfied(skipped.boundary_rows));
    s.attempts = 1;
    s.values[0] = s.values[0].add(M31.one());
    var changed = try draw.prepare(a, s);
    defer changed.deinit();
    try std.testing.expect(!try boundariesSatisfied(changed.boundary_rows));
    s.attempts = 0;
    try std.testing.expectError(error.InvalidBlake3Draw, draw.prepare(a, s));
    s.attempts = 1;
    s.start = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidBlake3Draw, draw.trusted(a, s));
    s.start -= 1;
    var edge = try draw.trusted(a, s);
    defer edge.deinit();
    try std.testing.expectEqual(std.math.maxInt(u64), edge.next_draw);
    s.namespace = core.fields.m31.Modulus - 1;
    try std.testing.expectError(error.InvalidBlake3Draw, draw.trusted(a, s));
}
fn allocationCase(a: std.mem.Allocator, s: draw.Statement) !void {
    var prepared = try draw.prepare(a, s);
    defer prepared.deinit();
    var fixed = try draw.trusted(a, s);
    defer fixed.deinit();
}
fn boundariesSatisfied(rows: []const draw.boundary.Row) !bool {
    const lang = @import("../../air/lang/mod.zig");
    const a = std.testing.allocator;
    var definition = try draw.boundary.build(a);
    defer definition.deinit();
    for (rows) |row| {
        const values = try @import("test_support.zig").evaluateArena(a, &definition.arena, &row);
        defer a.free(values);
        for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    }
    return true;
}

// Consecutive single calls discard each block's upper half; no reservoir reuse.
fn singleDraws(base: draw.Statement) !void {
    const a = std.testing.allocator;
    var channel = core.channel.blake3.Channel{ .digest = base.state, .n_draws = base.start };
    for (0..2) |_| {
        var s = base;
        s.start = channel.n_draws;
        s.consumption = .one;
        s.values[0..4].* = channel.drawSecureFelt().toM31Array();
        // Ignored output coordinates must neither bind nor emit a wire.
        @memset(s.values[4..], M31.fromCanonical(12345));
        var live = try draw.prepare(a, s);
        defer live.deinit();
        var fixed = try draw.trusted(a, s);
        defer fixed.deinit();
        try std.testing.expectEqual(channel.n_draws, live.next_draw);
        try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
        const row = live.challenge_rows[0];
        for (0..8) |i| try std.testing.expectEqual(@as(u32, if (i < 4) 1 else 0), row[76 + i].toU32());
        for (live.boundary_rows, fixed.boundary_rows) |actual, expected| try std.testing.expectEqualSlices(M31, actual[4..], expected[4..]);
        for (live.challenge_rows, fixed.challenge_rows) |actual, expected| try std.testing.expectEqualSlices(M31, actual[71..], expected[71..]);
        var full_statement = s;
        full_statement.consumption = .two;
        var full = try draw.trusted(a, full_statement);
        defer full.deinit();
        try std.testing.expectEqual(full.boundary_rows.len - 4, live.boundary_rows.len);
    }
}
