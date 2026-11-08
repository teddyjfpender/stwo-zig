const std = @import("std");
const word = @import("../blake3_memory_word.zig");
const tree = @import("../../../air/memory_commitment/blake3_state_tree.zig");
const M = @import("stwo_core").fields.m31.M31;
const boundary = @import("../blake3_memory_boundary.zig");
const binding = @import("../universal_relation_binding.zig");
const lang = @import("../../../air/lang/mod.zig");

test "BLAKE3 Span memory word binds all byte limbs through one word path to address clock and root" {
    const a = std.testing.allocator;
    const snapshot = [_]tree.Leaf{ .{ .index = 0, .value = 7 }, .{ .index = 3, .value = 0xffff002a }, .{ .index = 900, .value = 8 } };
    const hasher = tree.TreeHasher.init(.memory);
    const statement = word.Statement{ .address = 12, .clock = 123, .direction = .initial, .source_circuit = 99, .path_namespace = 100, .root = try hasher.root(&snapshot) };
    var live = try word.prepare(a, statement, &snapshot);
    defer live.deinit();
    var fixed = try word.trusted(a, statement);
    defer fixed.deinit();
    try std.testing.expectEqualSlices(M, live.boundary_row[4..], fixed.boundary_row[4..]);
    for (live.paths) |item| {
        try std.testing.expectEqual(statement.root, item.computed_root.?);
        const expected = try statement.wordPath();
        try std.testing.expectEqual(@as(u32, 3), expected.address);
        try std.testing.expectEqualSlices(M, live.boundary_row[0..4], item.input[0..4]);
    }
    try std.testing.expect(try closed(&live));
    live.boundary_row[1] = M.one();
    try std.testing.expect(!try closed(&live));
    var wrong = statement;
    wrong.root.bytes[31] ^= 0x80;
    try std.testing.expectError(error.MemorySnapshotRootMismatch, word.prepare(a, wrong, &snapshot));
    wrong = statement;
    wrong.source_circuit = 160;
    try std.testing.expectError(error.InvalidMemoryWordNamespace, wrong.validate());
}
fn closed(prepared: *const word.Prepared) !bool {
    const a = std.testing.allocator;
    var ledger = std.AutoHashMap([6]u32, M).init(a);
    defer ledger.deinit();
    try append(boundary, &ledger, &.{prepared.boundary_row});
    for (prepared.paths) |item| {
        inline for (.{ @import("../blake3_g_call.zig"), @import("../blake3_xor_call.zig"), @import("../blake3_boundary.zig"), @import("../blake3_byte_route.zig"), @import("../blake3_private_word.zig"), @import("../blake3_input_bridge.zig") }, .{ item.g_rows, item.xor_rows, item.boundary_rows, item.route_rows, item.word_rows, &@as([1]@import("../blake3_input_bridge.zig").Row, .{item.input}) }) |Air, rows| try append(Air, &ledger, rows);
    }
    var values = ledger.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}
fn append(comptime Air: type, ledger: *std.AutoHashMap([6]u32, M), rows: []const Air.Row) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try binding.Binding(Air).authenticate(&definition);
    for (rows) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.schema != lang.relation.id(.recursion_wire)) continue;
        var key: [6]u32 = undefined;
        for (&key, entry.values[0..6]) |*value, coordinate| value.* = (try coordinate.tryIntoM31()).toU32();
        const slot = try ledger.getOrPut(key);
        if (!slot.found_existing) slot.value_ptr.* = M.zero();
        slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
    };
}
