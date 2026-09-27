//! Compare omitted rows with the actual typed padding used by the native parent.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const native = @import("blake3_native_parent_rows.zig");
test "native typed padding census compares complete interaction columns" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = f.Channel{};
    const relations = try f.universal.UniversalRelations.draw(a, &channel);
    var different: usize = 0;
    inline for (native.Airs, 0..) |Air, index| {
        var def = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
        defer def.deinit();
        const plan = try f.binding.Binding(Air).authenticate(&def);
        var padding: Air.Row = @splat(f.M31.zero());
        if (@hasDecl(Air, "PROOF_KIND_PARAMETER_COUNT")) padding[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
        const rows = [_]Air.Row{padding} ** 4;
        const row_columns = @import("blake3_row_columns.zig");
        var explicit_counters = [2]f.Counter{ try f.Counter.init(a, .bitwise), try f.Counter.init(a, .range_check_8_8) };
        defer for (&explicit_counters) |*counter| counter.deinit(a);
        try row_columns.register(Air, &plan, &rows, &explicit_counters);
        for (0..5) |prefix| {
            var virtual_counters = [2]f.Counter{ try f.Counter.init(a, .bitwise), try f.Counter.init(a, .range_check_8_8) };
            defer for (&virtual_counters) |*counter| counter.deinit(a);
            try row_columns.register(Air, &plan, rows[0..prefix], &virtual_counters);
            try row_columns.registerRepeated(Air, &plan, padding, 4 - prefix, &virtual_counters);
            for (explicit_counters, virtual_counters) |left, right| for (left.values, right.values) |x, y| try std.testing.expect(x.eql(y));
        }
        const Runtime = f.framework.Runtime(f.binding.Binding(Air).Runtime);
        var explicit = try Runtime.generatePrepared(a, &plan, &rows, 2, &relations);
        defer explicit.deinit(a);
        var omitted = try Runtime.generatePrepared(a, &plan, &.{}, 2, &relations);
        defer omitted.deinit(a);
        for (0..4) |prefix| {
            var virtual = try Runtime.generatePreparedWithPadding(a, &plan, rows[0..prefix], 2, &relations, padding);
            defer virtual.deinit(a);
            try std.testing.expect(explicit.claimed_sum.eql(virtual.claimed_sum));
            for (explicit.columns, virtual.columns) |left, right| for (left, right) |x, y| try std.testing.expect(x.eql(y));
        }
        var equal = explicit.claimed_sum.eql(omitted.claimed_sum);
        for (explicit.columns, omitted.columns) |left, right| for (left, right) |x, y| { equal = equal and x.eql(y); };
        var live: usize = 0;
        for (plan.preparedEntries(padding)) |entry| live += @intFromBool(!entry.numerator.isZero());
        if (!equal) different += 1;
        std.debug.print("NATIVE_PADDING air={d} live_events={d} implicit_columns_equal={}\n", .{index, live, equal});
    }
    try std.testing.expect(different > 0);
}
