const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const air = @import("../qm31_sub_mul_v1.zig");
const support = @import("../test_support.zig");
const lang = @import("../../../air/lang/mod.zig");
const binding = @import("../universal_relation_binding.zig");
const Entry = @import("../relation_interaction.zig").Entry;
const schedule = air.Schedule{ .circuit = 1502, .minuend = 1, .subtrahend = 2, .factor = 3, .output = 5, .uses = 3 };
test "subtraction product pins degree two and rejects main mutations" {
    const a = std.testing.allocator;
    const digest = try air.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &air.SEMANTIC_DIGEST)) std.debug.print("SUB_MUL_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &digest);
    var definition = try air.build(a);
    defer definition.deinit();
    var degrees = try lang.degree.analyze(a, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    const row = try air.logicalRow(schedule, Q.fromU32Unchecked(2, 3, 5, 7), Q.fromU32Unchecked(11, 13, 17, 19), Q.fromU32Unchecked(23, 29, 31, 37));
    try satisfied(&definition, row, true);
    for (0..air.PHYSICAL_MAIN_COLUMN_COUNT) |col| {
        var changed = row;
        changed[col] = changed[col].add(M.one());
        try satisfied(&definition, changed, false);
    }
    const zero: air.Row = @splat(M.zero());
    try satisfied(&definition, zero, true);
    const plan = try binding.Binding(air).authenticate(&definition);
    for (plan.preparedEntries(zero)) |entry| try std.testing.expect(entry.numerator.isZero());
    var invalid = schedule;
    invalid.factor = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidQm31SubMul, air.logicalRow(invalid, Q.zero(), Q.zero(), Q.zero()));
}
test "subtraction product preserves signed lookup closure and fixed routing" {
    const a = std.testing.allocator;
    const linear = @import("../linear_ops.zig");
    const witness = @import("../linear_ops_witness.zig");
    const multiply = @import("../qm31_mul_add_v1.zig");
    var definition = try air.build(a);
    defer definition.deinit();
    var ld = try linear.build(a, .generated);
    defer ld.deinit();
    var md = try multiply.build(a);
    defer md.deinit();
    const fp = try binding.Binding(air).authenticate(&definition);
    const lp = try binding.Binding(linear).authenticate(&ld);
    const mp = try binding.Binding(multiply).authenticate(&md);
    const cases = [_][3]Q{
        .{ Q.zero(), Q.zero(), Q.zero() },
        .{ Q.one(), Q.one(), Q.fromU32Unchecked(0, 1, 0, 0) },
        .{ Q.fromU32Unchecked(core.fields.m31.Modulus - 1, 7, 13, 19), Q.fromU32Unchecked(2, 5, 11, 17), Q.fromU32Unchecked(3, 7, 11, 23) },
    };
    for (cases) |values| {
        const meta = witness.CircuitMetadata{ .circuit_id = M.fromCanonical(1502), .node_id = M.fromCanonical(4), .lhs_id = M.one(), .rhs_id = M.fromCanonical(2), .uses = M.one() };
        const lr = witness.logicalInputs(try witness.mainRow(.{ .operation = .sub, .lhs = values[0], .rhs = values[1], .circuit = meta }), witness.preprocessedRow(.{ .segment = .{ .operation = .sub, .circuit = meta } }), .segment_leaf);
        const mr = try multiply.logicalRow(.{ .circuit = 1502, .output = 5, .lhs = 4, .rhs = 3, .uses = 3 }, values[0].sub(values[1]), values[2], Q.zero());
        const row = try air.logicalRow(schedule, values[0], values[1], values[2]);
        try satisfied(&definition, row, true);
        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(a);
        try entries.appendSlice(a, &lp.preparedEntries(lr));
        try entries.appendSlice(a, &mp.preparedEntries(mr));
        const prefix = entries.items.len;
        var replacement = fp.preparedEntries(row);
        for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
        try entries.appendSlice(a, &replacement);
        try std.testing.expect(closed(entries.items));
        for (air.PHYSICAL_MAIN_COLUMN_COUNT..air.LOGICAL_INPUT_COUNT) |col| {
            var changed = row;
            changed[col] = changed[col].add(M.one());
            entries.shrinkRetainingCapacity(prefix);
            replacement = fp.preparedEntries(changed);
            for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
            try entries.appendSlice(a, &replacement);
            try std.testing.expect(!closed(entries.items));
        }
    }
}
test "subtraction product matcher preserves exports sharing and prior reservations" {
    const graph = @import("../composition_circuit.zig");
    const lower = @import("../verifier_arithmetic_lowering.zig");
    const matcher = @import("../detached_subtraction_product_plan.zig");
    for ([_]bool{ false, true }) |swap| {
        const nodes = [_]graph.Node{
            .{ .op = .input },                              .{ .op = .input },                                                                .{ .op = .input },
            .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .mul = .{ .lhs = if (swap) 2 else 3, .rhs = if (swap) 3 else 2 } } },
        };
        const outputs = [_]u32{4};
        const g = try graph.CircuitGraph.authenticate(&nodes, &outputs, graph.computeGraphDigest(&nodes, &outputs));
        var uses: [nodes.len]u32 = undefined;
        var lane = lower.Lane{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g };
        _ = try lower.computeLaneUseCountsInto(lane, &uses);
        var reserved: [nodes.len]bool = @splat(false);
        const match = matcher.matchAt(g, &uses, &reserved, 4).?;
        try std.testing.expectEqualDeep(matcher.Match{ .subtraction = 3, .output = 4, .minuend = 0, .subtrahend = 1, .factor = 2 }, match);
        reserved[3] = true;
        try std.testing.expectEqual(null, matcher.matchAt(g, &uses, &reserved, 4));
        reserved[3] = false;
        lane.exports = &.{.{ .node_id = 3, .uses = 1 }};
        _ = try lower.computeLaneUseCountsInto(lane, &uses);
        try std.testing.expectEqual(null, matcher.matchAt(g, &uses, &reserved, 4));
        lane.exports = &.{};
        _ = try lower.computeLaneUseCountsInto(lane, &uses);
        var matches: std.ArrayList(matcher.Match) = .empty;
        defer matches.deinit(std.testing.allocator);
        try matcher.reserve(&matches, std.testing.allocator, g, &uses, &reserved);
        try matcher.reserve(&matches, std.testing.allocator, g, &uses, &reserved);
        try std.testing.expectEqual(@as(usize, 1), matches.items.len);
        try std.testing.expect(reserved[3] and reserved[4]);
    }
}
fn satisfied(definition: *const air.Definition, row: air.Row, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    var valid = true;
    for (definition.constraints, 0..) |_, i| valid = valid and support.constraintAt(&definition.arena, &definition.constraints, values, i).isZero();
    try std.testing.expectEqual(expected, valid);
}
fn closed(entries: []const Entry) bool {
    for (entries) |key| {
        var sum = Q.zero();
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
