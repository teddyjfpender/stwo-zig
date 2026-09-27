const std = @import("std");
const core = @import("stwo_core");
const graph = @import("blake3_hash_plan.zig");
const witness = @import("blake3_hash_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;

test "BLAKE3 hash DAG matches standard hashing across blocks chunks and unbalanced trees" {
    const a = std.testing.allocator;
    var input: [8193]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for ([_]usize{ 0, 1, 3, 4, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 8193 }) |len| {
        var expected: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(input[0..len], &expected, .{});
        var prepared = try witness.prepare(a, 991, input[0..len], expected);
        defer prepared.rows.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &prepared.digest);
        var trusted = try witness.trustedRows(a, 991, input[0..len], expected);
        defer trusted.deinit();
        inline for (.{ g, xor, boundary }, .{ prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows }, .{ trusted.g_rows, trusted.xor_rows, trusted.boundary_rows }) |Air, actual, fixed| {
            for (actual, fixed) |left, right| try std.testing.expectEqualSlices(M31, left[Air.PHYSICAL_MAIN_COLUMN_COUNT..], right[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        var plan = try graph.build(a, len);
        defer plan.deinit();
        const chunks = @max(1, (len + 1023) / 1024);
        try std.testing.expectEqual(@max(1, (len + 63) / 64) + chunks - 1, plan.calls.len);
    }
    try std.testing.expectError(error.Blake3GraphTooLarge, graph.build(a, std.math.maxInt(usize)));
}

test "BLAKE3 hash global wires reject chaining flags and digest substitutions" {
    const a = std.testing.allocator;
    var input: [1025]u8 = @splat(37);
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&input, &digest, .{});
    var prepared = try witness.prepare(a, 73, &input, digest);
    defer prepared.rows.deinit();
    try std.testing.expect(try closed(&prepared.rows));
    // First G of block two consumes the previous compression's CV directly.
    const saved = prepared.rows.g_rows[56][0];
    prepared.rows.g_rows[56][0] = saved.add(M31.one());
    try std.testing.expect(!try closed(&prepared.rows));
    prepared.rows.g_rows[56][0] = saved;
    // Fixed initial flags are public-boundary sources, not witness authority.
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    const flags_wire = plan.calls[plan.calls.len - 1].initial[15];
    var found_flags = false;
    for (plan.sources, 0..) |source, i| if (source.wire == flags_wire) {
        found_flags = true;
        const row = prepared.rows.boundary_rows[i];
        prepared.rows.boundary_rows[i][0] = row[0].add(M31.one());
        prepared.rows.boundary_rows[i][8] = prepared.rows.boundary_rows[i][0];
        try std.testing.expect(!try closed(&prepared.rows));
        prepared.rows.boundary_rows[i] = row;
        break;
    };
    try std.testing.expect(found_flags);
    const last = prepared.rows.boundary_rows.len - 1;
    prepared.rows.boundary_rows[last][0] = prepared.rows.boundary_rows[last][0].add(M31.one());
    prepared.rows.boundary_rows[last][8] = prepared.rows.boundary_rows[last][0];
    try std.testing.expect(!try closed(&prepared.rows));
}
fn closed(rows: *const witness.Rows) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M31).init(a);
    defer counts.deinit();
    inline for (.{ g, xor, boundary }, .{ rows.g_rows, rows.xor_rows, rows.boundary_rows }) |Air, values| {
        var d = try Air.build(a);
        defer d.deinit();
        const plan = try binding.Binding(Air).authenticate(&d);
        for (values) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M31.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}

test "BLAKE3 hash graph releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var plan = try graph.build(a, 1025);
    defer plan.deinit();
    var prepared = try witness.prepare(a, 19, "allocation boundary", @splat(0));
    defer prepared.rows.deinit();
}
