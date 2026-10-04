const std = @import("std");
const core = @import("stwo_core");
const ro = @import("../readonly_consistency.zig");
const M = core.fields.m31.M31;
const schedule = ro.Schedule{ .table = 700, .chain = 701, .rank = 1, .last = false };
test "Read-only consistency pins sorted sparse table semantics and full u32 indices" {
    const a = std.testing.allocator;
    const digest = try ro.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &ro.SEMANTIC_DIGEST)) std.debug.print("readonly identity: {s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqualSlices(u8, &ro.SEMANTIC_DIGEST, &digest);
    var d = try ro.build(a);
    defer d.deinit();
    const plan = try @import("../universal_relation_binding.zig").Binding(ro).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, ro.SEMANTIC_DIGEST, ro.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(ro, a, &direct, &plan);
    defer exported.deinit();
    const pairs = [_][2]u32{ .{ 0, 0 }, .{ 0, 1 }, .{ 255, 256 }, .{ 65535, 65536 }, .{ 0xffffff, 0x1000000 }, .{ 0, 0xffffffff }, .{ 0x7ffffffe, 0x7fffffff }, .{ 0x7fffffff, 0x80000000 }, .{ 0xfffffffe, 0xffffffff }, .{ 0xffffffff, 0xffffffff } };
    const fixed = try ro.fixedRow(schedule);
    for (pairs) |pair| {
        const row = try ro.logicalRow(schedule, .{ .index = pair[0], .value = M.one() }, .{ .index = pair[1], .value = M.one() });
        try std.testing.expect(try satisfied(&d, row));
        try std.testing.expectEqualSlices(M, fixed[19..], row[19..]);
        const entries = plan.preparedEntries(row);
        try std.testing.expectEqual(pair[1] & 65535, (try entries[6].values[1].tryIntoM31()).v);
        try std.testing.expectEqual(pair[1] >> 16, (try entries[6].values[2].tryIntoM31()).v);
        for (0..15) |i| {
            var bad = row;
            bad[i] = bad[i].add(M.one());
            try std.testing.expect(!try satisfied(&d, bad));
        }
        var bad = row;
        bad[17] = bad[17].add(M.one());
        try std.testing.expect(!try satisfied(&d, bad));
        if (pair[0] == pair[1]) {
            bad = row;
            bad[15] = bad[15].add(M.one());
            try std.testing.expect(!try satisfied(&d, bad));
        }
    }
    try std.testing.expect(try satisfied(&d, @splat(M.zero())));
    const initial = try ro.logicalRow(.{ .table = 700, .chain = 701, .rank = 0, .last = true }, .{ .index = 0, .value = M.zero() }, .{ .index = 0, .value = M.fromCanonical(19) });
    try std.testing.expect(try satisfied(&d, initial));
    try std.testing.expectError(error.InconsistentReadonlyValue, ro.logicalRow(schedule, .{ .index = 1, .value = M.one() }, .{ .index = 1, .value = M.zero() }));
    try std.testing.expectError(error.InvalidReadonlyConsistency, ro.logicalRow(schedule, .{ .index = 2, .value = M.one() }, .{ .index = 1, .value = M.one() }));
    try std.testing.expectError(error.InvalidReadonlyConsistency, ro.fixedRow(.{ .table = 700, .chain = 700, .rank = 0, .last = true }));
    // Integer equations alone admit byte 256; the typed lookup excludes it.
    var alias = try ro.logicalRow(schedule, .{ .index = 0, .value = M.one() }, .{ .index = 256, .value = M.one() });
    alias[0] = M.fromCanonical(256);
    alias[1] = M.zero();
    alias[8] = M.fromCanonical(256);
    alias[9] = M.zero();
    alias[18] = try M.fromCanonical(256).inv();
    try std.testing.expect(try satisfied(&d, alias));
    try std.testing.expect((try plan.preparedEntries(alias)[0].values[0].tryIntoM31()).v > 255);
}
fn satisfied(d: *const ro.Definition, row: ro.Row) !bool {
    const a = std.testing.allocator;
    const values = try @import("../test_support.zig").evaluateArena(a, &d.arena, &row);
    defer a.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
test "Read-only consistency verifies unsorted duplicate inputs in a complete CPU proof" {
    const f = @import("../blake3_proof_fixture.zig");
    const input_air = @import("../readonly_input.zig");
    const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ ro, input_air });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const input = [_]ro.Entry{ .{ .index = 0xffffffff, .value = M.one() }, .{ .index = 0, .value = M.fromCanonical(9) }, .{ .index = 256, .value = M.fromCanonical(3) }, .{ .index = 0x7fffffff, .value = M.fromCanonical(13) }, .{ .index = 0, .value = M.fromCanonical(9) }, .{ .index = 256, .value = M.fromCanonical(3) } };
    const sorted = try a.dupe(ro.Entry, &input);
    std.mem.sort(ro.Entry, sorted, {}, struct {
        fn less(_: void, l: ro.Entry, r: ro.Entry) bool {
            return l.index < r.index;
        }
    }.less);
    var actual: [input.len]ro.Row = undefined;
    var fixed: [input.len]ro.Row = undefined;
    var previous = ro.Entry{ .index = 0, .value = M.zero() };
    for (sorted, 0..) |entry, i| {
        const s = ro.Schedule{ .table = 700, .chain = 701, .rank = @intCast(i), .last = i + 1 == sorted.len };
        actual[i] = try ro.logicalRow(s, previous, entry);
        fixed[i] = try ro.fixedRow(s);
        previous = entry;
    }
    var boundaries: [input.len * 2 + 1]f.boundary.Row = undefined;
    var input_rows: [input.len]input_air.Row = undefined;
    var fixed_inputs: [input.len]input_air.Row = undefined;
    for (input, 0..) |entry, i| {
        const port = input_air.Schedule{ .index = .{ .circuit = 702, .wire = @intCast(2 * i) }, .value = .{ .circuit = 702, .wire = @intCast(2 * i + 1) }, .table = 700 };
        input_rows[i] = try input_air.logicalRow(port, entry.index, entry.value);
        fixed_inputs[i] = try input_air.fixedRow(port);
        boundaries[2 * i] = try f.boundary.logicalRow(702, @intCast(2 * i), M.one(), entry.index);
        boundaries[2 * i + 1] = try f.boundary.logicalCoordinates(702, @intCast(2 * i + 1), M.one(), .{ entry.value, M.zero(), M.zero(), M.zero() });
    }
    boundaries[input.len * 2] = try f.boundary.logicalCoordinates(701, 0, M.one(), @splat(M.zero()));
    const logs = [5]u32{ 1, 1, 4, 3, 3 };
    const rows = .{ try f.padded(f.g, a, &.{}, 1), try f.padded(f.xor, a, &.{}, 1), try f.padded(f.boundary, a, &boundaries, 4), try f.padded(ro, a, &actual, 3), try f.padded(input_air, a, &input_rows, 3) };
    var pp: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ rows[0], rows[1], &boundaries, &fixed, &fixed_inputs }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &pp);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &pp);
    const trusted = try pp.toOwnedSlice(a);
    boundaries[0][9] = boundaries[0][9].add(M.one());
    pp = .empty;
    inline for (F.Airs, .{ rows[0], rows[1], &boundaries, &fixed, &fixed_inputs }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &pp);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &pp);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, try pp.toOwnedSlice(a));
}

test "Read-only input authenticates byte indices scalar values and stable table tuples" {
    const adapter = @import("../readonly_input.zig");
    const a = std.testing.allocator;
    const digest = try adapter.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &adapter.SEMANTIC_DIGEST)) std.debug.print("readonly input identity: {s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqualSlices(u8, &adapter.SEMANTIC_DIGEST, &digest);
    var d = try adapter.build(a);
    defer d.deinit();
    const plan = try @import("../universal_relation_binding.zig").Binding(adapter).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, adapter.SEMANTIC_DIGEST, adapter.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(adapter, a, &direct, &plan);
    defer exported.deinit();
    const port = adapter.Schedule{ .index = .{ .circuit = 1, .wire = 0 }, .value = .{ .circuit = 1, .wire = 1 }, .table = 2 };
    const fixed = try adapter.fixedRow(port);
    for ([_]u32{ 0, 255, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff }) |index| {
        const row = try adapter.logicalRow(port, index, M.one());
        try std.testing.expectEqualSlices(M, fixed[5..], row[5..]);
        const entries = plan.preparedEntries(row);
        try std.testing.expectEqual(index & 65535, (try entries[2].values[1].tryIntoM31()).v);
        try std.testing.expectEqual(index >> 16, (try entries[2].values[2].tryIntoM31()).v);
        try std.testing.expect(entries[2].values[3].eql(entries[1].values[2]));
        for (entries[1].values[3..6]) |zero| try std.testing.expect(zero.isZero());
    }
    try std.testing.expectError(error.InvalidReadonlyInput, adapter.fixedRow(.{ .index = port.index, .value = port.index, .table = 2 }));
}
