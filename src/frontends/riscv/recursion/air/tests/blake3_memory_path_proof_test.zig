//! Diagnostic CPU STARK gate for a full-depth byte-memory opening.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const tree = @import("../../../air/memory_commitment/blake3_state_tree.zig");
const path = @import("../blake3_memory_path.zig");
const route = @import("../blake3_byte_route.zig");
const word = @import("../blake3_private_word.zig");
const bridge = @import("../blake3_input_bridge.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ route, word, bridge });

test "BLAKE3 memory path proves all 30 levels and rejects a changed root" {
    try proveOpening(.memory, 255);
}
test "BLAKE3 memory path proves a full canonical program field" {
    try proveOpening(.program, 0x7ffffffe);
}
fn proveOpening(kind: tree.Kind, byte: u32) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hasher = tree.TreeHasher.init(kind);
    const address: u32 = 0x1234567;
    const snapshot = [_]tree.Leaf{ .{ .index = 0, .value = 7 }, .{ .index = address, .value = byte }, .{ .index = tree.MEMORY_WORD_LIMIT - 1, .value = 42 } };
    const opening = try hasher.opening(&snapshot, address);
    const root = opening.root;
    const siblings = opening.siblings;
    const statement = path.Statement{ .namespace = 100, .source = .{ .circuit = 99, .wire = 0 }, .kind = kind, .address = address, .root = root };
    var live = try path.prepare(a, statement, byte, &siblings);
    defer live.deinit();
    const boundaries = try addSource(a, &live, statement, byte);
    const logs = [_]u32{ log(live.g_rows.len), log(live.xor_rows.len), log(boundaries.len), log(live.route_rows.len), log(live.word_rows.len), 1 };
    const rows = .{ try f.padded(f.g, a, live.g_rows, logs[0]), try f.padded(f.xor, a, live.xor_rows, logs[1]), try f.padded(f.boundary, a, boundaries, logs[2]), try f.padded(route, a, live.route_rows, logs[3]), try f.padded(word, a, live.word_rows, logs[4]), try f.padded(bridge, a, &.{live.input}, logs[5]) };
    const trusted = try preprocessing(a, statement, byte, logs);
    var wrong = statement;
    wrong.root.bytes[31] ^= 0x80;
    const false_pp = try preprocessing(a, wrong, byte, logs);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn log(n: usize) u32 {
    return @max(1, std.math.log2_int_ceil(usize, n));
}
fn addSource(a: std.mem.Allocator, prepared: *const path.Prepared, statement: path.Statement, byte: u32) ![]f.boundary.Row {
    // Fixture-only public byte producer; production memory admission replaces it.
    const source = try f.boundary.logicalRow(statement.source.circuit, statement.source.wire, f.M31.one(), byte);
    return std.mem.concat(a, f.boundary.Row, &.{ prepared.boundary_rows, &.{source} });
}
fn preprocessing(a: std.mem.Allocator, statement: path.Statement, byte: u32, logs: [6]u32) ![]f.Column {
    var fixed = try path.trusted(a, statement);
    defer fixed.deinit();
    const boundaries = try addSource(a, &fixed, statement, byte);
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g_rows, fixed.xor_rows, boundaries, fixed.route_rows, fixed.word_rows, &@as([1]bridge.Row, .{fixed.input}) }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
