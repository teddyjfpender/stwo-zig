//! External bounded words and canonical fields feed private transcript state.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const t = @import("blake3_transcript_witness.zig");
const word = @import("blake3_private_word.zig");
const encoding = @import("blake3_field_bytes.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ t.challenge, t.route, t.query_mask, word, encoding });
const words = [_]u32{ 0, 0xffffffff, 0x80000000, 17 };
const fields = [_]f.QM31{f.QM31.fromU32Unchecked(1, 2147483646, 23, 91)};
fn operations(raw: []const u32, secure: []const f.QM31) [2]t.Operation {
    return .{ .{ .routed_words = .{ .values = raw, .source = .{ .circuit = 10, .first_wire = 0 } } }, .{ .routed_felts = .{ .values = secure, .source = .{ .circuit = 11, .first_wire = 0 } } } };
}
test "BLAKE3 routed transcript payloads preserve fixed schedules and own read receipts" {
    const a = std.testing.allocator;
    try privateRootTranscript(a);
    const ops = operations(&words, &fields);
    var live = try t.prepare(a, 100, &ops);
    defer live.deinit();
    const zero_words: [4]u32 = @splat(0);
    const zero_fields = [_]f.QM31{f.QM31.zero()};
    const placeholders = operations(&zero_words, &zero_fields);
    var changed = try t.prepare(a, 100, &placeholders);
    defer changed.deinit();
    var fixed = try t.trusted(a, 100, &placeholders);
    defer fixed.deinit();
    try sameFixed(live, changed);
    try sameFixed(live, fixed);
    try std.testing.expectEqual(@as(usize, 2), live.payload_reads.len);
    for (live.payload_reads, fixed.payload_reads, 0..) |actual, expected, i| {
        try std.testing.expectEqual(i, actual.operation);
        try std.testing.expectEqualDeep(actual.source, expected.source);
        try std.testing.expectEqualSlices(u32, actual.uses, expected.uses);
        try std.testing.expectEqual(@as(usize, 4), actual.uses.len);
        for (actual.uses) |uses| try std.testing.expect(uses > 0);
    }
    var native = f.Channel{};
    native.mixU32s(&words);
    native.mixFelts(&fields);
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &live.final_digest.?);
    try std.testing.expect(!std.mem.eql(u8, &live.final_digest.?, &changed.final_digest.?));
    try std.testing.expect(fixed.final_digest == null);
    for ([_]u32{ 100, 101, 102 }) |alias| {
        var bad = ops;
        bad[0].routed_words.source.circuit = alias;
        try std.testing.expectError(error.InvalidBlake3Transcript, t.trusted(a, 100, &bad));
    }
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    // Exported outputs carry protocol identities and no fixed challenge values.
    var native_draw = f.Channel{};
    const draw_values = try native_draw.drawSecureFelts(a, 2);
    defer a.free(draw_values);
    var coords: [8]f.M31 = undefined;
    coords[0..4].* = draw_values[0].toM31Array();
    coords[4..8].* = draw_values[1].toM31Array();
    var draw_ops = [_]t.Operation{.{ .secure = .{ .output = .{ .universal = 3 }, .attempts = @intCast(native_draw.n_draws), .consumption = .two, .values = coords } }};
    var exported = try t.prepare(a, 100, &draw_ops);
    defer exported.deinit();
    draw_ops[0].secure.values = @splat(f.M31.zero());
    var independent = try t.trusted(a, 100, &draw_ops);
    defer independent.deinit();
    try sameFixed(exported, independent);
    try std.testing.expectEqualDeep(exported.draw_outputs, independent.draw_outputs);
    try std.testing.expectEqual(@as(usize, 1), exported.draw_outputs.len);
    const receipt = exported.draw_outputs[0];
    // Public compatibility mode adds exactly one sink per accepted coordinate.
    draw_ops[0].secure.output = null;
    var public = try t.trusted(a, 100, &draw_ops);
    defer public.deinit();
    try std.testing.expectEqual(@as(usize, 0), public.draw_outputs.len);
    try std.testing.expectEqual(exported.boundary_rows.len + 8, public.boundary_rows.len);
    try std.testing.expectEqual(@as(usize, 8), receipt.words);
    try std.testing.expectEqual(@as(usize, 3), receipt.role.universal);
    try std.testing.expectEqual(@as(u32, @intCast(100 + 2 * native_draw.n_draws)), receipt.source.circuit);
    for (exported.boundary_rows) |row| try std.testing.expect(row[5].v != receipt.source.circuit or row[6].v >= 8);
}
fn sameFixed(left: t.Prepared, right: t.Prepared) !void {
    inline for (.{ t.g, t.xor, t.boundary, t.challenge, t.route, t.query_mask }, .{ "g_rows", "xor_rows", "boundary_rows", "challenge_rows", "route_rows", "query_rows" }) |Air, name| {
        try std.testing.expectEqual(@field(left, name).len, @field(right, name).len);
        for (@field(left, name), @field(right, name)) |a, b| try std.testing.expectEqualSlices(f.M31, a[Air.PHYSICAL_MAIN_COLUMN_COUNT..], b[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
}
fn allocationCase(a: std.mem.Allocator) !void {
    const ops = operations(&words, &fields);
    var live = try t.prepare(a, 100, &ops);
    defer live.deinit();
}
test "BLAKE3 private routed words and canonical fields verify in a transcript proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var native = f.Channel{};
    native.mixU32s(&words);
    native.mixFelts(&fields);
    var output: [8]f.M31 = @splat(f.M31.zero());
    output[0..4].* = native.drawSecureFelt().toM31Array();
    const ops = operations(&words, &fields) ++ [_]t.Operation{.{ .secure = .{ .attempts = @intCast(native.n_draws), .values = output } }};
    var live = try t.prepare(a, 100, &ops);
    defer live.deinit();
    var fixed_ops = ops;
    const zero_words: [4]u32 = @splat(0);
    const zero_fields = [_]f.QM31{f.QM31.zero()};
    fixed_ops[0].routed_words.values = &zero_words;
    fixed_ops[1].routed_felts.values = &zero_fields;
    var fixed = try t.trusted(a, 100, &fixed_ops);
    defer fixed.deinit();
    try sameFixed(live, fixed);
    var live_words: [4]word.Row = undefined;
    var fixed_words: [4]word.Row = undefined;
    for (&live_words, &fixed_words, words, live.payload_reads[0].uses, 0..) |*row, *trusted, value, uses, i| {
        row.* = try word.logicalRow(10, @intCast(i), uses, value);
        trusted.* = try word.logicalRow(10, @intCast(i), uses, 0);
    }
    const schedule = encoding.Schedule{ .source_circuit = 12, .source_wire = 0, .destination_circuit = 11, .destination_first = 0, .uses = live.payload_reads[1].uses[0..4].* };
    const encoded = [_]encoding.Row{try encoding.logicalRow(schedule, fields[0])};
    const trusted_encoded = [_]encoding.Row{try encoding.fixedRow(schedule)};
    const source = try f.boundary.privateCoordinates(12, 0, f.M31.one(), fields[0].toM31Array());
    const placeholder = try f.boundary.privateCoordinates(12, 0, f.M31.one(), @splat(f.M31.zero()));
    const bounds = try std.mem.concat(a, f.boundary.Row, &.{ live.boundary_rows, &.{source} });
    const trusted_bounds = try std.mem.concat(a, f.boundary.Row, &.{ fixed.boundary_rows, &.{placeholder} });
    const unpadded = .{ live.g_rows, live.xor_rows, bounds, live.challenge_rows, live.route_rows, live.query_rows, &live_words, &encoded };
    const trusted_rows = .{ fixed.g_rows, fixed.xor_rows, trusted_bounds, fixed.challenge_rows, fixed.route_rows, fixed.query_rows, &fixed_words, &trusted_encoded };
    var logs: [8]u32 = undefined;
    comptime var row_types: [8]type = undefined;
    inline for (F.Airs, 0..) |Air, i| row_types[i] = []Air.Row;
    var rows: std.meta.Tuple(&row_types) = undefined;
    inline for (F.Airs, 0..) |Air, i| {
        logs[i] = if (unpadded[i].len <= 1) 1 else std.math.log2_int_ceil(usize, unpadded[i].len);
        rows[i] = try f.padded(Air, a, unpadded[i], logs[i]);
    }
    const trusted = try preprocessing(a, trusted_rows, logs);
    trusted_bounds[0][8] = trusted_bounds[0][8].add(f.M31.one());
    const wrong = try preprocessing(a, trusted_rows, logs);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, wrong);
}
fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [8]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn privateRootTranscript(a: std.mem.Allocator) !void {
    var ops = [_]t.Operation{.{ .routed_root = .{ .value = @splat(0xa7), .source = .{ .circuit = 10, .first_wire = 16 } } }};
    var live = try t.prepare(a, 100, &ops);
    defer live.deinit();
    var native = f.Channel{};
    native.mixRoot(ops[0].routed_root.value);
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &live.final_digest.?);
    ops[0].routed_root.value = @splat(0x91);
    var changed = try t.prepare(a, 100, &ops);
    defer changed.deinit();
    var fixed = try t.trusted(a, 100, &ops);
    defer fixed.deinit();
    try sameFixed(live, changed);
    try sameFixed(live, fixed);
    try std.testing.expect(!std.mem.eql(u8, &live.final_digest.?, &changed.final_digest.?));
    try std.testing.expectEqual(@as(usize, 1), live.root_reads.len);
    try std.testing.expectEqualDeep(live.root_reads, fixed.root_reads);
    for (live.root_reads[0].uses) |uses| try std.testing.expect(uses > 0);
    try std.testing.expectEqualDeep(ops[0].routed_root.source, live.root_reads[0].source);
    const public_ops = [_]t.Operation{.{ .root = ops[0].routed_root.value }};
    var public = try t.trusted(a, 100, &public_ops);
    defer public.deinit();
    try std.testing.expectEqual(@as(usize, 0), public.root_reads.len);
    try std.testing.expectEqual(live.boundary_rows.len + 8, public.boundary_rows.len);
    for ([_]u32{ 100, 101, 102 }) |alias| {
        ops[0].routed_root.source.circuit = alias;
        try std.testing.expectError(error.InvalidBlake3Transcript, t.trusted(a, 100, &ops));
    }
}
