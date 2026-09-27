const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const bounded = @import("blake3_bounded_draw.zig");
const fixture = @import("blake3_rejection_fixture.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ bounded.draw.challenge, bounded.draw.route, bounded.control, bounded.counter });
fn statement() bounded.Statement {
    return .{ .namespace = 601, .capacity = 3, .state = fixture.STATE, .state_source = .{ .circuit = 500, .first_wire = 0 }, .start = 0, .counter_source = .{ .circuit = 501, .first_wire = 0 } };
}
test "BLAKE3 bounded draws preserve private counters and native retries" {
    const a = std.testing.allocator;
    const s = statement();
    var live = try bounded.prepare(a, s);
    defer live.deinit();
    var fixed = try bounded.trusted(a, s);
    defer fixed.deinit();
    try sameFixed(live, fixed);
    try std.testing.expectEqual(@as(?u64, 2), live.next_counter);
    try std.testing.expectEqual(@as(u32, 0), live.rows.counter_rows[2][0].v);
    try std.testing.expectEqualSlices(f.M31, live.rows.counter_rows[2][1..9], live.rows.counter_rows[2][9..17]);
    var native = f.Channel{ .digest = s.state, .n_draws = s.start };
    const expected = try native.drawSecureFelts(a, 2);
    defer a.free(expected);
    try std.testing.expectEqual(native.n_draws, live.next_counter.?);
    try std.testing.expectEqualSlices(f.M31, &(expected[0].toM31Array() ++ expected[1].toM31Array()), &live.selected.?);
    for ([_]u64{ 1, 0xffffffff, 0xfffffffffffffffe }) |start| {
        var other_statement = s;
        other_statement.start = start;
        var other = try bounded.prepare(a, other_statement);
        defer other.deinit();
        try sameFixed(live, other);
        var oracle = f.Channel{ .digest = s.state, .n_draws = start };
        const actual = try oracle.drawSecureFelts(a, 2);
        defer a.free(actual);
        try std.testing.expectEqual(oracle.n_draws, other.next_counter.?);
        try std.testing.expectEqualSlices(f.M31, &(actual[0].toM31Array() ++ actual[1].toM31Array()), &other.selected.?);
    }
    try destinationCase(a, s, true);
    try std.testing.checkAllAllocationFailures(a, destinationCase, .{ s, false });
    var bad = s;
    bad.capacity = 1;
    try std.testing.expectError(error.Blake3RetryCapacityExhausted, bounded.prepare(a, bad));
    bad = s;
    bad.start = std.math.maxInt(u64);
    try std.testing.expectError(error.Blake3CounterExhausted, bounded.prepare(a, bad));
    bad = s;
    bad.state_source.circuit = s.namespace;
    try std.testing.expectError(error.InvalidBoundedBlake3Draw, bounded.trusted(a, bad));
}
fn sameFixed(left: bounded.Prepared, right: bounded.Prepared) !void {
    inline for (F.Airs, .{ "g_rows", "xor_rows", "boundary_rows", "challenge_rows", "route_rows", "control_rows", "counter_rows" }) |Air, name| {
        try std.testing.expectEqual(@field(left.rows, name).len, @field(right.rows, name).len);
        for (@field(left.rows, name), @field(right.rows, name)) |l, r| try std.testing.expectEqualSlices(f.M31, l[Air.PHYSICAL_MAIN_COLUMN_COUNT..], r[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
}
test "BLAKE3 bounded retry and checked counter verify in one proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = statement();
    var live = try bounded.prepare(a, s);
    defer live.deinit();
    var fixed = try bounded.trusted(a, s);
    defer fixed.deinit();
    var anchors: [20]f.boundary.Row = undefined;
    for (live.state_uses, 0..) |uses, i| anchors[i] = try f.boundary.logicalRow(s.state_source.circuit, @intCast(i), f.M31.fromCanonical(uses), std.mem.readInt(u32, s.state[4 * i ..][0..4], .little));
    for (live.counter_uses, 0..) |uses, i| anchors[8 + i] = try f.boundary.logicalRow(s.counter_source.circuit, @intCast(i), f.M31.fromCanonical(uses), 0);
    for (0..2) |i| anchors[10 + i] = try f.boundary.logicalRow(live.final_counter.circuit, live.final_counter.first_wire + @as(u32, @intCast(i)), f.M31.one().neg(), @truncate(live.next_counter.? >> @as(u6, @intCast(32 * i))));
    for (live.selected.?, 0..) |value, i| anchors[12 + i] = try f.boundary.logicalCoordinates(live.output.circuit, @intCast(i), f.M31.one().neg(), .{ value, f.M31.zero(), f.M31.zero(), f.M31.zero() });
    const b = try std.mem.concat(a, f.boundary.Row, &.{ live.rows.boundary_rows, &anchors });
    const tb = try std.mem.concat(a, f.boundary.Row, &.{ fixed.rows.boundary_rows, &anchors });
    const raw = .{ live.rows.g_rows, live.rows.xor_rows, b, live.rows.challenge_rows, live.rows.route_rows, live.rows.control_rows, live.rows.counter_rows };
    const trusted = .{ fixed.rows.g_rows, fixed.rows.xor_rows, tb, fixed.rows.challenge_rows, fixed.rows.route_rows, fixed.rows.control_rows, fixed.rows.counter_rows };
    var logs: [7]u32 = undefined;
    comptime var types: [7]type = undefined;
    inline for (F.Airs, 0..) |Air, i| types[i] = []Air.Row;
    var rows: std.meta.Tuple(&types) = undefined;
    inline for (F.Airs, 0..) |Air, i| {
        logs[i] = if (raw[i].len <= 1) 1 else std.math.log2_int_ceil(usize, raw[i].len);
        rows[i] = try f.padded(Air, a, raw[i], logs[i]);
    }
    const pp = try preprocessing(a, trusted, logs);
    tb[tb.len - 10][8] = f.M31.fromCanonical(3);
    const wrong = try preprocessing(a, trusted, logs);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, pp, wrong);
}
fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [7]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn destinationCase(a: std.mem.Allocator, s: bounded.Statement, check_invalid: bool) !void {
    var expected = try bounded.prepare(a, s);
    defer expected.deinit();
    var fixed = try bounded.trusted(a, s);
    defer fixed.deinit();
    const counts = try bounded.requiredHashRows(a, s.capacity);
    const gs = try a.alloc(bounded.draw.g.Row, counts.g);
    defer a.free(gs);
    const xs = try a.alloc(bounded.draw.xor.Row, counts.xor);
    defer a.free(xs);
    const destination = bounded.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var actual = try bounded.prepareInto(a, s, destination);
        defer actual.deinit();
        try std.testing.expectEqual(gs.ptr, actual.rows.g_rows.ptr);
        try std.testing.expectEqualDeep(expected.rows, actual.rows);
        try std.testing.expectEqualDeep(expected.state_uses, actual.state_uses);
        try std.testing.expectEqualDeep(expected.counter_uses, actual.counter_uses);
        try std.testing.expectEqualDeep(expected.selected, actual.selected);
        try std.testing.expectEqual(expected.next_counter, actual.next_counter);
    }
    try std.testing.expectEqualDeep(expected.rows.g_rows, gs);
    {
        var actual = try bounded.trustedInto(a, s, destination);
        defer actual.deinit();
        try std.testing.expectEqualDeep(fixed.rows, actual.rows);
        try std.testing.expectEqualDeep(fixed.selected, actual.selected);
    }
    if (check_invalid) {
        @memset(gs, @splat(f.M31.fromCanonical(123)));
        var invalid = destination;
        invalid.xor_rows = xs[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, bounded.prepareInto(a, s, invalid));
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, bounded.trustedInto(a, s, invalid));
        for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    }
}
