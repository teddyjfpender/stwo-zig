const std = @import("std");
const core = @import("stwo_core");
const bridge = @import("blake3_input_bridge.zig");
const private = @import("blake3_private_hash_witness.zig");
const lang = @import("../../air/lang/mod.zig");
const binding = @import("universal_relation_binding.zig");
const M31 = core.fields.m31.M31;
test "BLAKE3 private input bridge pins typed semantics and enforces unused bytes" {
    const a = std.testing.allocator;
    const digest = try bridge.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &bridge.SEMANTIC_DIGEST, &digest);
    var d = try bridge.build(a);
    defer d.deinit();
    const plan = try binding.Binding(bridge).authenticate(&d);
    const direct = try @import("direct_constraint_program.zig").authenticate(&d.arena, bridge.SEMANTIC_DIGEST, bridge.LOGICAL_INPUT_COUNT);
    var exported = try @import("framework_polynomial_export_v1.zig").exportLocalPrepared(bridge, a, &direct, &plan);
    defer exported.deinit();
    for (1..5) |count| {
        const schedule = bridge.Schedule{ .source_circuit = 3, .source_wire = 5, .hash_circuit = 7, .hash_wire = 9, .uses = 14, .byte_count = @intCast(count) };
        var row = try bridge.logicalRow(schedule, if (count == 4) 0xffffffff else (@as(u32, 1) << @as(u5, @intCast(count * 8))) - 1);
        try std.testing.expect(try satisfied(&d, row));
        for (count..4) |byte| {
            row[byte] = M31.one();
            try std.testing.expect(!try satisfied(&d, row));
            row[byte] = M31.zero();
        }
        const entries = plan.preparedEntries(row);
        try std.testing.expectEqual(@as(u32, 3), (try entries[0].values[0].tryIntoM31()).toU32());
        try std.testing.expectEqual(@as(u32, 7), (try entries[1].values[0].tryIntoM31()).toU32());
        try std.testing.expect((try entries[0].numerator.tryIntoM31()).eql(M31.one().neg()));
        try std.testing.expect((try entries[1].numerator.tryIntoM31()).eql(M31.fromCanonical(14)));
        try std.testing.expectEqualSlices(core.fields.qm31.QM31, entries[0].values[2..6], entries[1].values[2..6]);
    }
}
fn satisfied(d: *const bridge.Definition, row: bridge.Row) !bool {
    const values = try @import("test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
test "BLAKE3 private hash preprocessing contains no message words" {
    const a = std.testing.allocator;
    const caller = private.Caller{ .circuit = 8, .first_wire = 31 };
    var input: [65]u8 = @splat(0xff);
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&input, &digest, .{});
    var live = try private.prepare(a, 19, caller, &input, digest);
    defer live.rows.deinit();
    var trusted = try private.trustedRows(a, 19, caller, input.len, digest);
    defer trusted.deinit();
    try std.testing.expectEqualSlices(u8, &digest, &live.digest);
    try std.testing.expectEqual(@as(usize, 17), live.rows.bridge_rows.len);
    for (live.rows.bridge_rows, trusted.bridge_rows) |row, fixed| try std.testing.expectEqualSlices(M31, row[4..], fixed[4..]);
    for (live.rows.hash_rows.boundary_rows, trusted.hash_rows.boundary_rows) |row, fixed| try std.testing.expectEqualSlices(M31, &row, &fixed);
    try std.testing.expectEqual(@as(u32, 255), live.rows.bridge_rows[16][0].toU32());
    for (live.rows.bridge_rows[16][1..4]) |byte| try std.testing.expect(byte.isZero());
    try std.testing.expectError(error.InvalidBlake3Caller, private.trustedRows(a, 8, caller, input.len, digest));
}

test "BLAKE3 private input claims require exact caller and graph endpoints" {
    const a = std.testing.allocator;
    const caller = private.Caller{ .circuit = 8, .first_wire = 31 };
    const input = "private bytes across a word boundary";
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(input, &digest, .{});
    var prepared = try private.prepare(a, 19, caller, input, digest);
    defer prepared.rows.deinit();
    try std.testing.expect(try closed(&prepared.rows, caller, input, true));
    try std.testing.expect(!try closed(&prepared.rows, caller, input, false));
    const saved = prepared.rows.bridge_rows[0];
    for ([_]usize{ 0, 4, 5, 6, 7, 8, 9 }) |coordinate| {
        prepared.rows.bridge_rows[0][coordinate] = saved[coordinate].add(M31.one());
        try std.testing.expect(!try closed(&prepared.rows, caller, input, true));
        prepared.rows.bridge_rows[0] = saved;
    }
}
fn closed(rows: *const private.Rows, caller: private.Caller, input: []const u8, include_caller: bool) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M31).init(a);
    defer counts.deinit();
    const g = @import("blake3_g_call.zig");
    const xor = @import("blake3_xor_call.zig");
    const boundary = @import("blake3_boundary.zig");
    inline for (.{ g, xor, boundary, bridge }, .{ rows.hash_rows.g_rows, rows.hash_rows.xor_rows, rows.hash_rows.boundary_rows, rows.bridge_rows }) |Air, data| {
        var d = try Air.build(a);
        defer d.deinit();
        const plan = try binding.Binding(Air).authenticate(&d);
        for (data) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M31.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    // Independent upstream fixture: each caller word emits once. Omitting it
    // must fail; the bridge never authenticates itself via its host witness.
    if (include_caller) for (0..input.len / 4 + @intFromBool(input.len % 4 != 0)) |i| {
        var key: [6]u32 = @splat(0);
        key[0] = caller.circuit;
        key[1] = caller.first_wire + @as(u32, @intCast(i));
        const len = @min(4, input.len - i * 4);
        for (input[i * 4 ..][0..len], 0..) |byte, j| key[2 + j] = byte;
        const slot = try counts.getOrPut(key);
        if (!slot.found_existing) slot.value_ptr.* = M31.zero();
        slot.value_ptr.* = slot.value_ptr.*.add(M31.one());
    };
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}
