//! Compare exact signed lookup multisets across the proposed graph contraction.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const fused = @import("../native_pcs_opening4_v1.zig");
const old = @import("../detached_opening_accumulate4_v1.zig");
const input = @import("../scalar_wire_source.zig");
const binding = @import("../universal_relation_binding.zig");
const Entry = @import("../relation_interaction.zig").Entry;

test "native PCS opening preserves both external authentication consumers" {
    const allocator = std.testing.allocator;
    const digest = try fused.computeSemanticDigest(allocator);
    if (!std.mem.eql(u8, &digest, &fused.SEMANTIC_DIGEST)) std.debug.print("NATIVE_PCS_OPENING4_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqualSlices(u8, &fused.SEMANTIC_DIGEST, &digest);
    var fused_def = try fused.build(allocator);
    defer fused_def.deinit();
    var old_def = try old.build(allocator);
    defer old_def.deinit();
    var input_def = try input.build(allocator);
    defer input_def.deinit();
    var degrees = try @import("../../../air/lang/mod.zig").degree.analyze(allocator, &fused_def.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    const fused_plan = try binding.Binding(fused).authenticate(&fused_def);
    const old_plan = try binding.Binding(old).authenticate(&old_def);
    const input_plan = try binding.Binding(input).authenticate(&input_def);
    const nodes: [4]u32 = .{ 101, 102, 103, 104 };
    const weights: [4]QM31 = @splat(QM31.fromU32Unchecked(2, 3, 5, 7));
    const queries: [4]M31 = .{ M31.zero(), M31.one(), M31.fromCanonical(3), M31.fromCanonical(core.fields.m31.Modulus - 1) };
    const accumulator = QM31.fromU32Unchecked(11, 13, 17, 19);
    var output = accumulator;
    var lhs: [4]QM31 = undefined;
    for (queries, weights, &lhs) |q, w, *value| {
        value.* = QM31.fromU32Unchecked(q.toU32(), 0, 0, 0);
        output = output.add(value.mul(w));
    }
    var closure_schedule = fused.Schedule{ .circuit = 1502, .accumulator = 0, .queries = undefined, .weights = .{ 11, 12, 13, 14 }, .output = 90, .uses = 7 };
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(allocator);
    for (0..4) |term| {
        closure_schedule.queries[term] = nodes[term];
        const row = try input.logicalRow(closure_schedule.circuit, nodes[term], 3, queries[term]);
        try entries.appendSlice(allocator, &input_plan.preparedEntries(row));
    }
    const old_row = try old.logicalRow(.{ .circuit = closure_schedule.circuit, .accumulator = closure_schedule.accumulator, .lhs = nodes, .rhs = closure_schedule.weights, .output = closure_schedule.output, .uses = closure_schedule.uses }, accumulator, lhs, weights, output);
    try entries.appendSlice(allocator, &old_plan.preparedEntries(old_row));
    const prefix = entries.items.len;
    const row = try fused.logicalRow(closure_schedule, accumulator, queries, weights, output);
    var replacement = fused_plan.preparedEntries(row);
    for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
    try entries.appendSlice(allocator, &replacement);
    try std.testing.expect(closed(entries.items));
    // Every fixed coordinate must remain bound, including zero-valued queries.
    for (fused.PHYSICAL_MAIN_COLUMN_COUNT..fused.LOGICAL_INPUT_COUNT) |column| {
        var changed = row;
        changed[column] = changed[column].add(M31.one());
        entries.shrinkRetainingCapacity(prefix);
        replacement = fused_plan.preparedEntries(changed);
        for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
        try entries.appendSlice(allocator, &replacement);
        try std.testing.expect(!closed(entries.items));
    }
}
fn closed(entries: []const Entry) bool {
    for (entries) |key| {
        var sum = QM31.zero();
        for (entries) |entry| {
            if (entry.schema != key.schema or entry.schema_version != key.schema_version or entry.domain != key.domain or entry.arity != key.arity) continue;
            var equal = true;
            for (entry.values[0..entry.arity], key.values[0..key.arity]) |a, b| equal = equal and a.eql(b);
            if (equal) sum = sum.add(entry.numerator);
        }
        if (!sum.isZero()) return false;
    }
    return true;
}

const air = fused;
const support = @import("../test_support.zig");
const lang = @import("../../../air/lang/mod.zig");
const schedule = air.Schedule{ .circuit = 1502, .accumulator = 10, .queries = .{ 101, 102, 103, 104 }, .weights = .{ 21, 22, 23, 24 }, .output = 90, .uses = 3 };
test "native PCS opening rejects main mutations and admits inert padding" {
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
    invalid.queries[2] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidNativePcsOpening4, air.logicalRow(invalid, QM31.zero(), @splat(M31.zero()), @splat(QM31.zero()), QM31.zero()));
}
fn satisfied(definition: *const air.Definition, row: air.Row, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    var valid = true;
    for (definition.constraints, 0..) |_, index| valid = valid and support.constraintAt(&definition.arena, &definition.constraints, values, index).isZero();
    try std.testing.expectEqual(expected, valid);
}
