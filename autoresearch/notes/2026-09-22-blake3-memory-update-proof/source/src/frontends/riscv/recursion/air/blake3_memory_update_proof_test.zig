//! Diagnostic proof of one byte change with shared private siblings.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const tree = @import("../../air/memory_commitment/blake3_byte_tree.zig");
const update = @import("blake3_memory_update.zig");
const route = @import("blake3_byte_route.zig");
const word = @import("blake3_private_word.zig");
const bridge = @import("blake3_input_bridge.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ route, word, bridge });
const Rows = std.meta.Tuple(&.{ []f.g.Row, []f.xor.Row, []f.boundary.Row, []route.Row, []word.Row, []bridge.Row });
test "BLAKE3 memory update proves shared siblings and rejects changed after root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hasher = tree.TreeHasher.init(.memory);
    const before = [_]tree.Leaf{ .{ .index = 0, .value = 7 }, .{ .index = 12, .value = 42 }, .{ .index = 900, .value = 8 } };
    var after = before;
    after[1].value = 255;
    const opening = try hasher.opening(&before, 12);
    const statement = update.Statement{ .namespace = 100, .kind = .memory, .address = 12, .before_source = .{ .circuit = 99, .wire = 0 }, .after_source = .{ .circuit = 99, .wire = 1 }, .before_root = opening.root, .after_root = try hasher.root(&after) };
    var live = try update.prepare(a, statement, 42, 255, &opening.siblings);
    defer live.deinit();
    const assembled = try assemble(a, &live, statement);
    var logs: [6]u32 = undefined;
    var rows: Rows = undefined;
    inline for (F.Airs, assembled, 0..) |Air, values, i| {
        logs[i] = @max(1, std.math.log2_int_ceil(usize, values.len));
        rows[i] = try f.padded(Air, a, values, logs[i]);
    }
    const trusted = try preprocessing(a, statement, logs);
    var wrong = statement;
    wrong.after_root.bytes[31] ^= 0x80;
    const false_pp = try preprocessing(a, wrong, logs);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn assemble(a: std.mem.Allocator, p: *const update.Prepared, s: update.Statement) !Rows {
    // Public byte fixtures; production memory relations replace these sources.
    const sources = [_]f.boundary.Row{ try f.boundary.logicalRow(s.before_source.circuit, s.before_source.wire, f.M31.one(), 42), try f.boundary.logicalRow(s.after_source.circuit, s.after_source.wire, f.M31.one(), 255) };
    return .{
        try std.mem.concat(a, f.g.Row, &.{ p.before.g_rows, p.after.g_rows }),
        try std.mem.concat(a, f.xor.Row, &.{ p.before.xor_rows, p.after.xor_rows }),
        try std.mem.concat(a, f.boundary.Row, &.{ p.before.boundary_rows, p.after.boundary_rows, &sources }),
        try std.mem.concat(a, route.Row, &.{ p.before.route_rows, p.after.route_rows }),
        try std.mem.concat(a, word.Row, &.{ p.before.word_rows, p.after.word_rows }),
        try a.dupe(bridge.Row, &.{ p.before.input, p.after.input }),
    };
}
fn preprocessing(a: std.mem.Allocator, statement: update.Statement, logs: [6]u32) ![]f.Column {
    var fixed = try update.trusted(a, statement);
    defer fixed.deinit();
    const rows = try assemble(a, &fixed, statement);
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, rows, 0..) |Air, values, i| try f.project(Air, a, values, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
