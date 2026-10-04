const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lang = @import("../../../air/lang/mod.zig");
const air = @import("../detached_pcs_opening4_v1.zig");
const support = @import("../test_support.zig");
const binding = @import("../universal_relation_binding.zig").Binding(air);
const schedule = air.Schedule{ .circuit = 412, .verifier = 2, .accumulator = 10, .queries = .{
    .{ .tree = 0, .column = 7, .query = 13 }, .{ .tree = 1, .column = 8, .query = 14 },
    .{ .tree = 2, .column = 9, .query = 15 }, .{ .tree = 3, .column = 10, .query = 16 },
}, .weights = .{ 21, 22, 23, 24 }, .output = 90, .uses = 3 };

test "fused PCS opening pins degree-two semantics and exact query-wire relations" {
    const actual = try air.computeSemanticDigest(std.testing.allocator);
    if (!std.mem.eql(u8, &actual, &air.SEMANTIC_DIGEST)) std.debug.print("PCS_OPENING4_DIGEST={s}\n", .{std.fmt.bytesToHex(actual, .lower)});
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &actual);
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var degrees = try lang.degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    _ = try binding.authenticate(&definition);
    const queries: [4]M31 = .{ M31.fromCanonical(3), M31.fromCanonical(5), M31.fromCanonical(7), M31.fromCanonical(11) };
    const weights: [4]QM31 = @splat(QM31.fromU32Unchecked(2, 3, 5, 7));
    const accumulator = QM31.fromU32Unchecked(17, 19, 23, 29);
    var output = accumulator;
    for (queries, weights) |q, w| output = output.add(w.mul(QM31.fromU32Unchecked(q.toU32(), 0, 0, 0)));
    const row = try air.logicalRow(schedule, accumulator, queries, weights, output);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.events, 0..) |id, index| {
        const event = definition.arena.effect(id).?;
        const tuple = definition.arena.effectValues(id).?;
        const query_event = index > 0 and index < 9 and index % 2 == 1;
        try std.testing.expectEqual(lang.relation.id(if (query_event) .recursion_trace_query_value else .recursion_wire), event.binding.?.schema);
        try std.testing.expectEqual(if (index == 9) lang.relation.Role.emit else lang.relation.Role.consume, event.binding.?.role);
        const expected: []const u32 = if (query_event) blk: {
            const t = (index - 1) / 2;
            const q = schedule.queries[t];
            break :blk &.{ schedule.verifier, q.tree, q.column, q.query, queries[t].toU32() };
        } else blk: {
            const node = if (index == 0) schedule.accumulator else if (index == 9) schedule.output else schedule.weights[(index - 2) / 2];
            const value = if (index == 0) accumulator else if (index == 9) output else weights[(index - 2) / 2];
            const limbs = value.toM31Array();
            break :blk &.{ schedule.circuit, node, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() };
        };
        try std.testing.expectEqual(expected.len, tuple.len);
        for (tuple, expected) |word, want| try std.testing.expectEqual(want, values[lang.types.idIndex(word)].toU32());
        try std.testing.expectEqual(if (index == 9) @as(u32, 3) else @as(u32, 1), values[lang.types.idIndex(event.liveness.?)].toU32());
    }
}

test "fused PCS opening rejects every main-coordinate mutation and admits inert padding" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    for (0..12) |case| {
        const seed: u32 = @intCast(case * 43);
        const accumulator = QM31.fromU32Unchecked(seed + 2, seed + 3, seed + 5, seed + 7);
        var queries: [4]M31 = undefined;
        var weights: [4]QM31 = undefined;
        var output = accumulator;
        for (&queries, &weights, 0..) |*q, *w, term| {
            const n: u32 = seed + @as(u32, @intCast(term * 13));
            q.* = M31.fromCanonical(n + 11);
            w.* = QM31.fromU32Unchecked(n + 17, n + 19, n + 23, n + 29);
            output = output.add(w.mul(QM31.fromU32Unchecked(q.toU32(), 0, 0, 0)));
        }
        const row = try air.logicalRow(schedule, accumulator, queries, weights, output);
        try satisfied(&definition, row, true);
        for (0..air.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
            var changed = row;
            changed[column] = changed[column].add(M31.one());
            try satisfied(&definition, changed, false);
        }
    }
    const padding: air.Row = @splat(M31.zero());
    try satisfied(&definition, padding, true);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &padding);
    defer std.testing.allocator.free(values);
    for (definition.events) |id| try std.testing.expect(values[lang.types.idIndex(definition.arena.effect(id).?.liveness.?)].isZero());
    var invalid = schedule;
    invalid.queries[2].column = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidDetachedPcsOpening4, air.logicalRow(invalid, QM31.zero(), @splat(M31.zero()), @splat(QM31.zero()), QM31.zero()));
}
fn satisfied(definition: *const air.Definition, row: air.Row, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    var valid = true;
    for (definition.constraints, 0..) |_, index| valid = valid and support.constraintAt(&definition.arena, &definition.constraints, values, index).isZero();
    try std.testing.expectEqual(expected, valid);
}

test "fused PCS opening binds every schedule coordinate and handles zero and field-edge values" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const queries: [4]M31 = .{ M31.zero(), M31.one(), M31.fromCanonical(core.fields.m31.Modulus - 1), M31.fromCanonical(core.fields.m31.Modulus - 2) };
    const weights: [4]QM31 = .{ QM31.one(), QM31.zero(), QM31.fromU32Unchecked(core.fields.m31.Modulus - 1, 3, 5, 7), QM31.fromU32Unchecked(11, core.fields.m31.Modulus - 1, 17, 19) };
    var output = QM31.zero();
    for (queries, weights) |q, w| output = output.add(w.mul(QM31.fromU32Unchecked(q.toU32(), 0, 0, 0)));
    const row = try air.logicalRow(schedule, QM31.zero(), queries, weights, output);
    try satisfied(&definition, row, true);
    const base = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(base);
    for (0..air.PREPROCESSED_COLUMN_COUNT) |column| {
        var changed = row;
        const slot = air.PHYSICAL_MAIN_COLUMN_COUNT + column;
        changed[slot] = changed[slot].add(M31.one());
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &changed);
        defer std.testing.allocator.free(values);
        var differs = false;
        for (definition.events) |id| {
            const event = definition.arena.effect(id).?;
            const live = lang.types.idIndex(event.liveness.?);
            differs = differs or !base[live].eql(values[live]);
            for (definition.arena.effectValues(id).?) |word| {
                const index = lang.types.idIndex(word);
                differs = differs or !base[index].eql(values[index]);
            }
        }
        try std.testing.expect(differs);
    }
    // A zero query makes its weight irrelevant to local arithmetic, but the
    // weight remains a consumed wire: lookup equality must still bind it.
    var changed = row;
    changed[9] = changed[9].add(M31.one());
    try satisfied(&definition, changed, true);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &changed);
    defer std.testing.allocator.free(values);
    const weight_tuple = definition.arena.effectValues(definition.events[2]).?;
    try std.testing.expect(!base[lang.types.idIndex(weight_tuple[2])].eql(values[lang.types.idIndex(weight_tuple[2])]));
}
