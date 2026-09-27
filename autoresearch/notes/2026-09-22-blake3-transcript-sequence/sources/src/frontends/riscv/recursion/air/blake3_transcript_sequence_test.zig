const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const sequence = @import("blake3_transcript_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ sequence.challenge, sequence.route });
fn operations() [5]sequence.Operation {
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU64(198);
    const first = secure(&channel);
    const second = secure(&channel);
    channel.mixU64(42);
    return .{ .{ .integer = 198 }, first, second, .{ .integer = 42 }, secure(&channel) };
}
fn secure(channel: *f.core.channel.blake3.Channel) sequence.Operation {
    const start = channel.n_draws;
    var values: [8]f.M31 = @splat(f.M31.zero());
    values[0..4].* = channel.drawSecureFelt().toM31Array();
    return .{ .secure = .{ .attempts = @intCast(channel.n_draws - start), .values = values } };
}
test "BLAKE3 transcript sequence derives native counters resets and private state links" {
    const a = std.testing.allocator;
    const ops = operations();
    var live = try sequence.prepare(a, 901, &ops);
    defer live.deinit();
    var fixed = try sequence.trusted(a, 901, &ops);
    defer fixed.deinit();
    try std.testing.expectEqual(@as(u64, 1), live.next_draw);
    try std.testing.expectEqual(@as(usize, 3), live.challenge_rows.len);
    inline for (F.Airs, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.challenge_rows, live.route_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.challenge_rows, fixed.route_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(f.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    var wrong = ops;
    wrong[4] = ops[2]; // Reuse the pre-reset challenge instead of the reset draw.
    var changed = try sequence.prepare(a, 901, &wrong);
    defer changed.deinit();
    try std.testing.expect(!try boundariesSatisfied(changed.boundary_rows));
    wrong[1].secure.attempts = 0;
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trusted(a, 901, &wrong));
    try std.testing.expectError(error.InvalidBlake3Transcript, sequence.trusted(a, f.core.fields.m31.Modulus - 2, &ops));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    const ops = operations();
    var prepared = try sequence.prepare(a, 901, ops[0..2]);
    defer prepared.deinit();
    var fixed = try sequence.trusted(a, 901, ops[0..2]);
    defer fixed.deinit();
}
fn boundariesSatisfied(rows: []const sequence.boundary.Row) !bool {
    const lang = @import("../../air/lang/mod.zig");
    const a = std.testing.allocator;
    var definition = try sequence.boundary.build(a);
    defer definition.deinit();
    for (rows) |row| {
        const values = try @import("test_support.zig").evaluateArena(a, &definition.arena, &row);
        defer a.free(values);
        for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    }
    return true;
}
test "BLAKE3 native transcript sequence verifies in a complete CPU proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ops = operations();
    var live = try sequence.prepare(a, 901, &ops);
    defer live.deinit();
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.g_rows, logs[0]), try f.padded(f.xor, a, live.xor_rows, logs[1]), try f.padded(f.boundary, a, live.boundary_rows, logs[2]), try f.padded(sequence.challenge, a, live.challenge_rows, logs[3]), try f.padded(sequence.route, a, live.route_rows, logs[4]) };
    const trusted = try preprocessing(a, &ops);
    var wrong = ops;
    wrong[4].secure.values[0] = wrong[4].secure.values[0].add(f.M31.one());
    const false_pp = try preprocessing(a, &wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, ops: []const sequence.Operation) ![]f.Column {
    var data = try sequence.trusted(a, 901, ops);
    defer data.deinit();
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
