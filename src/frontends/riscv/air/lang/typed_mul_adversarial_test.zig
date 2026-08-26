//! Adversarial row-local closure for native RV32 `MUL`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const corpus = @import("typed_mul_corpus.zig");
const eval_support = @import("typed_load_store_test_support.zig");
const typed_mul = @import("typed_mul.zig");
const types = @import("types.zig");

test "typed MUL forged low product survives direct roots only to fail carry range" {
    var definition = try typed_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var row = corpus.honestRow(17); // 1 * 1, ordinary non-alias destination.
    row[33] = m(2); // forged product byte
    row[9] = m(2); // keep destination-result equality coherent
    const values = try evaluate(&definition, &row);
    defer std.testing.allocator.free(values);

    try expectAllDirectZero(&definition, values);
    const fields = definition.arena.effectValues(effectId(9)).?;
    try std.testing.expectEqual(@as(u32, 2), at(values, fields[0]).toU32());
    try std.testing.expect(at(values, fields[1]).toU32() >= 1 << 11);
}

test "typed MUL rejects non-byte product even with coherent destination" {
    var definition = try typed_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var row = corpus.honestRow(17);
    row[33] = m(256);
    row[9] = m(256);
    const values = try evaluate(&definition, &row);
    defer std.testing.allocator.free(values);

    try expectAllDirectZero(&definition, values);
    const fields = definition.arena.effectValues(effectId(9)).?;
    try std.testing.expectEqual(@as(u32, 256), at(values, fields[0]).toU32());
}

test "typed MUL source write-back forgery is rejected directly" {
    var definition = try typed_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var row = corpus.honestRow(17);
    row[19] = m(2); // rs1.next[0] no longer equals rs1.previous[0].
    const values = try evaluate(&definition, &row);
    defer std.testing.allocator.free(values);
    try std.testing.expect(!constraintValue(&definition, values, 8).isZero());
}

test "typed MUL destination and placement forgeries are rejected" {
    var definition = try typed_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();

    {
        var x0_row = corpus.honestRow(0);
        x0_row[37] = M31.one();
        const values = try evaluate(&definition, &x0_row);
        defer std.testing.allocator.free(values);
        try std.testing.expect(!constraintValue(&definition, values, 3).isZero());
    }

    {
        var misplaced = corpus.honestRow(17);
        misplaced[typed_mul.MAIN_COLUMN_COUNT] = M31.zero();
        const values = try evaluate(&definition, &misplaced);
        defer std.testing.allocator.free(values);
        try std.testing.expect(!constraintValue(&definition, values, 16).isZero());
    }
}

fn evaluate(
    definition: *const typed_mul.Definition,
    row: *const [corpus.ROW_WIDTH]M31,
) ![]M31 {
    const values = try std.testing.allocator.alloc(M31, definition.arena.nodeCount());
    errdefer std.testing.allocator.free(values);
    var bindings: [corpus.ROW_WIDTH]eval_support.Binding = undefined;
    for (definition.columns.physical(), bindings[0..typed_mul.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_mul.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed_mul.MAIN_COLUMN_COUNT,
    };
    try eval_support.evaluateInto(&definition.arena, &bindings, row, values);
    return values;
}

fn expectAllDirectZero(definition: *const typed_mul.Definition, values: []const M31) !void {
    for (definition.model.constraints) |id|
        try std.testing.expect(constraintValueById(definition, values, id).isZero());
}

fn constraintValue(
    definition: *const typed_mul.Definition,
    values: []const M31,
    index: usize,
) M31 {
    return constraintValueById(definition, values, definition.model.constraints[index]);
}

fn constraintValueById(
    definition: *const typed_mul.Definition,
    values: []const M31,
    id: types.ConstraintId,
) M31 {
    return at(values, definition.arena.constraint(id).?.root);
}

fn effectId(index: usize) types.EffectId {
    return types.idFromIndex(types.EffectId, index) catch unreachable;
}

fn at(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
}

fn m(value: u32) M31 {
    return M31.fromCanonical(value);
}
