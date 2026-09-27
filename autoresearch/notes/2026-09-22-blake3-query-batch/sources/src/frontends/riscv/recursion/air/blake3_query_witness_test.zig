const std = @import("std");
const core = @import("stwo_core");
const query = @import("blake3_query_witness.zig");
const M31 = core.fields.m31.M31;
test "BLAKE3 query batches preserve native partial blocks counters and private fixed columns" {
    const a = std.testing.allocator;
    for ([_]usize{ 0, 1, 7, 8, 9, 17 }) |count| {
        var channel = core.channel.blake3.Channel{};
        channel.n_draws = 5;
        const native = try core.queries.drawQueries(&channel, a, 31, count);
        defer a.free(native);
        const values = try a.alloc(u32, count);
        defer a.free(values);
        for (values, native) |*value, word| value.* = @intCast(word);
        const s = query.Statement{ .namespace = 50, .state = channel.digestBytes(), .state_source = .{ .circuit = 1, .first_wire = 80 }, .start = 5, .log_domain_size = 31, .values = values };
        var live = try query.prepare(a, s);
        defer live.deinit();
        var placeholder = s;
        placeholder.state = @splat(0);
        var fixed = try query.trusted(a, placeholder);
        defer fixed.deinit();
        try std.testing.expectEqual(channel.n_draws, live.next_draw);
        try std.testing.expectEqual(count, live.mask_rows.len);
        for (live.mask_rows, values) |row, expected| {
            var actual: u32 = 0;
            for (row[4..8], 0..) |byte, i| actual |= byte.toU32() << @as(u5, @intCast(i * 8));
            try std.testing.expectEqual(expected, actual);
        }
        inline for (.{ query.g, query.xor, query.boundary, query.mask, query.route }, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.mask_rows, live.route_rows }, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.mask_rows, fixed.route_rows }) |Air, actual, expected| {
            try std.testing.expectEqual(actual.len, expected.len);
            for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        if (count == 0) try std.testing.expectEqualDeep(@as([8]u32, @splat(0)), live.state_uses);
        if (count == 9) {
            try std.testing.checkAllAllocationFailures(a, allocationCase, .{s});
            var bad = s;
            bad.start = std.math.maxInt(u64);
            try std.testing.expectError(error.InvalidBlake3Queries, query.trusted(a, bad));
            bad = s;
            bad.namespace = core.fields.m31.Modulus - 1;
            try std.testing.expectError(error.InvalidBlake3Queries, query.trusted(a, bad));
            bad = s;
            bad.state_source.circuit = s.namespace + 1;
            try std.testing.expectError(error.InvalidBlake3Queries, query.trusted(a, bad));
            bad = s;
            bad.values = &.{0x80000000};
            try std.testing.expectError(error.InvalidBlake3Queries, query.trusted(a, bad));
        }
    }
}
fn allocationCase(a: std.mem.Allocator, s: query.Statement) !void {
    var live = try query.prepare(a, s);
    defer live.deinit();
    var fixed = try query.trusted(a, s);
    defer fixed.deinit();
}
