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
    try realRejection();
    try singleDraws(s);
    try privateDraws(s);
    for ([_]bool{ false, true }) |private| {
        var other = s;
        other.attempts = 2;
        if (private) other.state_source = .{ .circuit = 41, .first_wire = 80 };
        for ([_]bool{ false, true }) |raw| {
            try destinationCase(a, other, raw, true);
            try std.testing.checkAllAllocationFailures(a, destinationCase, .{ other, raw, false });
        }
    }
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

fn privateDraws(base: draw.Statement) !void {
    const a = std.testing.allocator;
    var s = base;
    s.state_source = .{ .circuit = 41, .first_wire = 80 };
    var live = try draw.prepare(a, s);
    defer live.deinit();
    try std.testing.expect(live.route_rows.len > 0);
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    var placeholder = s;
    placeholder.state = @splat(0);
    var fixed = try draw.trusted(a, placeholder);
    defer fixed.deinit();
    inline for (.{ draw.g, draw.xor, draw.boundary, draw.challenge, draw.route }, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.challenge_rows, live.route_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.challenge_rows, fixed.route_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.expectEqualDeep(live.state_uses, fixed.state_uses);
    placeholder.attempts = 2;
    var twice = try draw.trusted(a, placeholder);
    defer twice.deinit();
    for (live.state_uses, twice.state_uses) |one, two| {
        try std.testing.expect(one > 0);
        try std.testing.expectEqual(one * 2, two);
    }
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{s});
    s.state_source.?.circuit = s.namespace + 1;
    try std.testing.expectError(error.InvalidBlake3Draw, draw.trusted(a, s));
}

fn realRejection() !void {
    const fixture = @import("blake3_rejection_fixture.zig");
    const a = std.testing.allocator;
    var native = core.channel.blake3.Channel{};
    native.mixU64(fixture.SEED);
    try std.testing.expectEqualSlices(u8, &fixture.STATE, &native.digestBytes());
    for (fixture.BLOCKS) |expected| try std.testing.expectEqualSlices(u32, &expected, &native.drawU32s());
    try std.testing.expect(core.channel.blake3.sampleWord(fixture.BLOCKS[0][0]) == null);
    // Start from the original initial state, not the already advanced digest.
    native = .{};
    native.mixU64(fixture.SEED);
    const values = try native.drawSecureFelts(a, 2);
    defer a.free(values);
    try std.testing.expectEqual(@as(u64, 2), native.n_draws);
    var coordinates: [8]M31 = undefined;
    for (&coordinates, fixture.BLOCKS[1]) |*coordinate, word| coordinate.* = core.channel.blake3.sampleWord(word) orelse return error.ExpectedAcceptedBlock;
    try std.testing.expectEqualSlices(M31, coordinates[0..4], &values[0].toM31Array());
    try std.testing.expectEqualSlices(M31, coordinates[4..8], &values[1].toM31Array());
    var s = draw.Statement{ .namespace = 601, .state = fixture.STATE, .start = 0, .attempts = 2, .values = coordinates };
    var live = try draw.prepare(a, s);
    defer live.deinit();
    var fixed = try draw.trusted(a, s);
    defer fixed.deinit();
    try std.testing.expect(try boundariesSatisfied(live.boundary_rows));
    try std.testing.expectEqual(@as(u32, 0), live.challenge_rows[0][70].v);
    try std.testing.expectEqual(@as(u32, 1), live.challenge_rows[1][70].v);
    inline for (.{ draw.g, draw.xor, draw.boundary, draw.challenge, draw.route }, .{ "g_rows", "xor_rows", "boundary_rows", "challenge_rows", "route_rows" }) |Air, name| {
        try std.testing.expectEqual(@field(live, name).len, @field(fixed, name).len);
        for (@field(live, name), @field(fixed, name)) |actual, expected| try std.testing.expectEqualSlices(M31, actual[Air.PHYSICAL_MAIN_COLUMN_COUNT..], expected[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    for ([_]u32{ 1, 3 }) |attempts| {
        s.attempts = attempts;
        var bad = try draw.prepare(a, s);
        defer bad.deinit();
        try std.testing.expect(!try boundariesSatisfied(bad.boundary_rows));
    }
}

fn destinationCase(a: std.mem.Allocator, s: draw.Statement, raw: bool, check_invalid: bool) !void {
    var expected = if (raw) try draw.prepareAttempts(a, s) else try draw.prepare(a, s);
    defer expected.deinit();
    var fixed = if (raw) try draw.trustedAttempts(a, s) else try draw.trusted(a, s);
    defer fixed.deinit();
    const counts = try draw.requiredHashRows(a, s.attempts);
    const gs = try a.alloc(draw.g.Row, counts.g);
    defer a.free(gs);
    const xs = try a.alloc(draw.xor.Row, counts.xor);
    defer a.free(xs);
    const destination = draw.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var actual = if (raw) try draw.prepareAttemptsInto(a, s, destination) else try draw.prepareInto(a, s, destination);
        defer actual.deinit();
        try std.testing.expectEqual(gs.ptr, actual.g_rows.ptr);
        inline for (.{ "g_rows", "xor_rows", "boundary_rows", "challenge_rows", "route_rows", "state_uses", "attempt_sources", "output_source", "next_draw" }) |name| try std.testing.expectEqualDeep(@field(expected, name), @field(actual, name));
    }
    try std.testing.expectEqualDeep(expected.g_rows, gs);
    {
        var actual = if (raw) try draw.trustedAttemptsInto(a, s, destination) else try draw.trustedInto(a, s, destination);
        defer actual.deinit();
        inline for (.{ "g_rows", "xor_rows", "boundary_rows", "challenge_rows", "route_rows", "state_uses", "attempt_sources", "output_source", "next_draw" }) |name| try std.testing.expectEqualDeep(@field(fixed, name), @field(actual, name));
    }
    if (check_invalid) {
        @memset(gs, @splat(M31.fromCanonical(123)));
        var invalid = destination;
        invalid.xor_rows = xs[1..];
        if (raw) {
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, draw.prepareAttemptsInto(a, s, invalid));
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, draw.trustedAttemptsInto(a, s, invalid));
        } else {
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, draw.prepareInto(a, s, invalid));
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, draw.trustedInto(a, s, invalid));
        }
        for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    }
}
