//! Full STARK gate for ordered native BLAKE3 draw admission.
const std = @import("std");
const core = @import("stwo_core");
const f = @import("../blake3_proof_fixture.zig");
const draw = @import("../blake3_draw_witness.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{draw.challenge});
test "BLAKE3 native draw produces constrained scalar challenges in a complete CPU proof" {
    for ([_]draw.Consumption{ .one, .two }) |consumption| try proveDraw(consumption);
}
fn proveDraw(consumption: draw.Consumption) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = core.channel.blake3.Channel{};
    channel.mixU64(198);
    channel.n_draws = 3;
    var statement = draw.Statement{ .namespace = 601, .state = channel.digestBytes(), .start = channel.n_draws, .attempts = 1, .values = @splat(f.M31.zero()), .consumption = consumption };
    if (consumption == .one) {
        statement.values[0..4].* = channel.drawSecureFelt().toM31Array();
    } else {
        const expected = try channel.drawSecureFelts(a, 2);
        statement.values = expected[0].toM31Array() ++ expected[1].toM31Array();
    }
    var live = try draw.prepare(a, statement);
    defer live.deinit();
    try std.testing.expectEqual(channel.n_draws, live.next_draw);
    const logs = live.logs();
    const rows = .{
        try f.padded(f.g, a, live.g_rows, logs[0]),
        try f.padded(f.xor, a, live.xor_rows, logs[1]),
        try f.padded(f.boundary, a, live.boundary_rows, logs[2]),
        try f.padded(draw.challenge, a, live.challenge_rows, logs[3]),
    };
    const trusted_pp = try preprocessing(a, statement);
    statement.values[2] = statement.values[2].add(f.M31.one());
    const false_pp = try preprocessing(a, statement);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted_pp, false_pp);
}
fn preprocessing(a: std.mem.Allocator, statement: draw.Statement) ![]f.Column {
    var fixed = try draw.trusted(a, statement);
    defer fixed.deinit();
    const logs = fixed.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.challenge_rows }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
