const std = @import("std");
const control = @import("../blake3_retry_control.zig");
const draw = @import("../blake3_draw_witness.zig");
const f = @import("../blake3_proof_fixture.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ draw.challenge, draw.route, control });
fn schedule(i: u32, source: control.Caller) control.Schedule {
    return .{ .pending = .{ .circuit = 700, .wire = i }, .status = .{ .circuit = source.circuit, .wire = 8 }, .next_pending = .{ .circuit = 700, .wire = i + 1 }, .values = source, .destination = .{ .circuit = 800, .first_wire = 0 }, .count_wire = 8, .ordinal = i + 1 };
}
test "BLAKE3 retry controller pins first acceptance and consumed count" {
    const a = std.testing.allocator;
    const digest = try control.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &control.SEMANTIC_DIGEST, &digest);
    var d = try control.build(a);
    defer d.deinit();
    const binding = try f.binding.Binding(control).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, control.SEMANTIC_DIGEST, control.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(control, a, &direct, &binding);
    defer exported.deinit();
    for (0..16) |pattern| {
        var pending: u1 = 1;
        var chosen: usize = 0;
        var consumed: usize = 0;
        for (0..4) |i| {
            const accept: u1 = @truncate(pattern >> @intCast(i));
            const s = schedule(@intCast(i), .{ .circuit = @intCast(100 + i), .first_wire = 0 });
            const row = try control.logicalRow(s, pending, accept, @splat(f.M31.fromCanonical(@intCast(i + 11))));
            const fixed = try control.fixedRow(s);
            try std.testing.expectEqualSlices(f.M31, fixed[12..], row[12..]);
            try std.testing.expect(try satisfied(&d, row));
            const entries = binding.preparedEntries(row);
            const selected = (try entries[19].numerator.tryIntoM31()).v;
            chosen += selected;
            if (selected == 1) consumed = (try entries[19].values[2].tryIntoM31()).v;
            for (0..4) |column| {
                var bad = row;
                bad[column] = if (column == 1) f.M31.fromCanonical(2) else bad[column].add(f.M31.one());
                try std.testing.expect(!try satisfied(&d, bad));
            }
            if (pending == 0) {
                // Padding may have either authentic acceptance bit; the status
                // lookup, not the local scan equation, binds its actual value.
                var other_status = row;
                other_status[1] = f.M31.one().sub(row[1]);
                try std.testing.expect(try satisfied(&d, other_status));
                const other = binding.preparedEntries(other_status);
                try std.testing.expect(!entries[1].values[2].eql(other[1].values[2]));
            }
            pending = @intCast(row[3].v);
        }
        try std.testing.expectEqual(@as(usize, if (pattern == 0) 0 else 1), chosen);
        try std.testing.expectEqual(@as(u1, if (pattern == 0) 1 else 0), pending);
        if (pattern != 0) try std.testing.expectEqual(@as(usize, @ctz(pattern)) + 1, consumed);
    }
    var single = schedule(0, .{ .circuit = 100, .first_wire = 0 });
    single.words = 4;
    const single_row = try control.logicalRow(single, 1, 1, @splat(f.M31.one()));
    const single_entries = binding.preparedEntries(single_row);
    for (0..8) |i| {
        try std.testing.expectEqual(i >= 4, single_entries[3 + 2 * i].numerator.isZero());
        try std.testing.expectEqual(i >= 4, single_entries[4 + 2 * i].numerator.isZero());
    }
    try std.testing.expect(try satisfied(&d, @splat(f.M31.zero())));
}
fn satisfied(d: *const control.Definition, row: control.Row) !bool {
    const values = try @import("../test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
test "BLAKE3 genuine retries select challenges and attempt count in a complete proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fixture = @import("../blake3_rejection_fixture.zig");
    const statement = draw.Statement{ .namespace = 601, .state = fixture.STATE, .start = 0, .attempts = 3, .values = @splat(f.M31.zero()) };
    var live = try draw.prepareAttempts(a, statement);
    defer live.deinit();
    var fixed = try draw.trustedAttempts(a, statement);
    defer fixed.deinit();
    var controls: [3]control.Row = undefined;
    var trusted_controls: [3]control.Row = undefined;
    var pending: u1 = 1;
    for (&controls, &trusted_controls, live.challenge_rows, live.attempt_sources, 0..) |*row, *trusted, challenge, source, i| {
        var values: [8]f.M31 = undefined;
        for (&values, 0..) |*value, j| value.* = challenge[j * 8 + 7];
        const s = schedule(@intCast(i), source);
        row.* = try control.logicalRow(s, pending, @intCast(challenge[70].v), values);
        trusted.* = try control.fixedRow(s);
        pending = @intCast(row.*[3].v);
    }
    try std.testing.expectEqual(@as(u1, 0), pending);
    try std.testing.expectEqual(@as(u32, 1), controls[1][2].v);
    try std.testing.expectEqual(@as(u32, 0), controls[2][2].v);
    var sinks: [11]f.boundary.Row = undefined;
    sinks[0] = try f.boundary.logicalCoordinates(700, 0, f.M31.one(), scalar(1));
    sinks[1] = try f.boundary.logicalCoordinates(700, 3, f.M31.one().neg(), scalar(0));
    sinks[2] = try f.boundary.logicalCoordinates(800, 8, f.M31.one().neg(), scalar(2));
    for (fixture.BLOCKS[1], sinks[3..], 0..) |value, *row, i| row.* = try f.boundary.logicalCoordinates(800, @intCast(i), f.M31.one().neg(), scalar((f.core.channel.blake3.sampleWord(value) orelse return error.ExpectedAcceptedBlock).v));
    const boundaries = try std.mem.concat(a, f.boundary.Row, &.{ live.boundary_rows, &sinks });
    const trusted_boundaries = try std.mem.concat(a, f.boundary.Row, &.{ fixed.boundary_rows, &sinks });
    const raw_rows = .{ live.g_rows, live.xor_rows, boundaries, live.challenge_rows, live.route_rows, &controls };
    const trusted_rows = .{ fixed.g_rows, fixed.xor_rows, trusted_boundaries, fixed.challenge_rows, fixed.route_rows, &trusted_controls };
    var logs: [6]u32 = undefined;
    comptime var types: [6]type = undefined;
    inline for (F.Airs, 0..) |Air, i| types[i] = []Air.Row;
    var rows: std.meta.Tuple(&types) = undefined;
    inline for (F.Airs, 0..) |Air, i| {
        logs[i] = if (raw_rows[i].len <= 1) 1 else std.math.log2_int_ceil(usize, raw_rows[i].len);
        rows[i] = try f.padded(Air, a, raw_rows[i], logs[i]);
    }
    const pp = try preprocessing(a, trusted_rows, logs);
    trusted_boundaries[trusted_boundaries.len - 9][8] = f.M31.fromCanonical(3);
    const wrong = try preprocessing(a, trusted_rows, logs);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, pp, wrong);
}
fn scalar(value: u32) [4]f.M31 {
    return .{ f.M31.fromCanonical(value), f.M31.zero(), f.M31.zero(), f.M31.zero() };
}
fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [6]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
