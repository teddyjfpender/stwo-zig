const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const Layout = @import("../block_v7_native_relation_layout_v1.zig");
const Original = @import("../block_v6_relation_layout_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
fn shapeFor(family: Opcode.OpcodeFamily) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = family, .log_size = 1, .n_rows = 1, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}

test "v7 actual-event layout preserves every opcode and register clock relation" {
    const a = std.testing.allocator;
    for (0..Opcode.N_FAMILIES) |ordinal| {
        var shape = shapeFor(@enumFromInt(ordinal));
        var full = try Original.Layout.init(a, &shape, 0, 1);
        defer full.deinit();
        var current = try Layout.Layout.init(a, &shape, 0, 1);
        defer current.deinit();
        try std.testing.expectEqual(full.slots.len - 1, current.slots.len);
        try std.testing.expect(!std.meta.eql(full.digest, current.digest));
        try Layout.requireCoverage(a, &shape, 0, 1, current.slots);
        if (Original.requireCoverage(a, &shape, 0, 1, current.slots)) |_| return error.WeakenedOldCoverage else |_| {}
        try std.testing.expectError(error.InvalidV7RelationCoverage, Layout.requireCoverage(a, &shape, 0, 1, full.slots));
        try std.testing.expectError(error.InvalidV7RelationCoverage, Layout.requireCoverage(a, &shape, 0, 1, current.slots[1..]));
        const changed = try a.dupe(Source.Slot, current.slots);
        defer a.free(changed);
        var register_clocks: usize = 0;
        var range_clocks: usize = 0;
        for (current.slots, 0..) |slot, index| {
            if (slot.kind != .lookup or slot.kind.lookup.source != .clock) continue;
            switch (slot.kind.lookup.partition) {
                .register_clock_memory_access => register_clocks += 1,
                .range_check_20, .range_check_8_8 => range_clocks += 1,
                else => return error.UnexpectedClockDisposition,
            }
            @memcpy(changed, current.slots);
            changed[index].kind.lookup.partition = .clock_memory_access;
            try std.testing.expectError(error.InvalidV7RelationCoverage, Layout.requireCoverage(a, &shape, 0, 1, changed));
        }
        try std.testing.expectEqual(@as(usize, 1), register_clocks);
        try std.testing.expectEqual(@as(usize, 2), range_clocks);
        @memcpy(changed, current.slots);
        changed[changed.len - 1] = changed[0];
        try std.testing.expectError(error.InvalidV7RelationCoverage, Layout.requireCoverage(a, &shape, 0, 1, changed));
        try std.testing.expectError(error.InvalidV7RelationCustodyMode, Layout.Layout.init(a, &shape, 0, 0));
    }
}

test "v7 clock disposition leaves actual RAM value and current clock binding intact" {
    const a = std.testing.allocator;
    const Universal = @import("../block_v5_opcode_memory_interaction_v1.zig");
    var channel = core.proof_suites.Blake3.Channel{};
    const drawn = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const elements = drawn.get(.memory_access);
    const M = core.fields.m31.M31;
    const row = Universal.Row{ .active = true, .consumed = .{ M.one(), M.fromCanonical(4096), M.fromCanonical(1048575), M.fromCanonical(17), M.zero(), M.zero(), M.zero() }, .emitted = .{ M.one(), M.fromCanonical(4096), M.fromCanonical(1500000), M.fromCanonical(23), M.zero(), M.zero(), M.zero() } };
    const blank = Universal.Row{ .active = false, .consumed = @splat(M.zero()), .emitted = @splat(M.zero()) };
    var generated = try Universal.generate(a, elements, &.{ row, blank }, 1);
    defer generated.deinit(a);
    var consumed: [7]Q = undefined;
    var emitted: [7]Q = undefined;
    for (&consumed, row.consumed) |*value, limb| value.* = Q.fromBase(limb);
    for (&emitted, row.emitted) |*value, limb| value.* = Q.fromBase(limb);
    const point = Universal.Point{ .active = Q.one(), .consumed = consumed, .emitted = emitted, .consume_term = Universal.read(&generated.columns, 0, 0), .emit_term = Universal.read(&generated.columns, 1, 0), .prefix = Universal.read(&generated.columns, 2, 0), .previous_prefix = Q.zero() };
    for (try Universal.constraints(elements, point, generated.claim, 2)) |value| try std.testing.expect(value.isZero());
    // Before byte, after byte and actual current clock are independently bound,
    // including a clock beyond the synthetic-gap threshold. No ghost claim can
    // compensate these original ordinary-access equations.
    for (0..3) |which| {
        var forged = point;
        switch (which) {
            0 => forged.consumed[3] = forged.consumed[3].add(Q.one()),
            1 => forged.emitted[3] = forged.emitted[3].add(Q.one()),
            2 => forged.emitted[2] = forged.emitted[2].add(Q.one()),
            else => unreachable,
        }
        var rejected = false;
        for (try Universal.constraints(elements, forged, generated.claim, 2)) |value| rejected = rejected or !value.isZero();
        try std.testing.expect(rejected);
    }
}
