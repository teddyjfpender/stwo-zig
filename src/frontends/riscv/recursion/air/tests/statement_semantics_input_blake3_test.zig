const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const span = @import("../../span_statement_blake3.zig");
const witness = @import("../statement_semantics_input_witness_blake3.zig");
const legacy = @import("../statement_semantics_input_witness.zig");
const component = @import("../statement_semantics_input.zig");
const support = @import("../test_support.zig");

fn bindings() [4 * span.SPAN_STATEMENT_CANONICAL_WORDS]witness.InputBinding {
    var result: [4 * span.SPAN_STATEMENT_CANONICAL_WORDS]witness.InputBinding = undefined;
    for (&result, 0..) |*binding, i| binding.* = .{
        .node_id = @intCast(i),
        .use_count = 1,
        .source = .{ .statement = .{
            .scope = @intCast(i / span.SPAN_STATEMENT_CANONICAL_WORDS),
            .index = @intCast(i % span.SPAN_STATEMENT_CANONICAL_WORDS),
            .active_kinds = .ALL,
        } },
    };
    return result;
}

test "BLAKE3 statement AIR witness binding has its own pinned identity" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(witness.BINDING_DIGEST_HEX, &std.fmt.bytesToHex(binding.identityDigest(), .lower));
    const executor = try witness.Executor.init(&definition, &binding);
    try std.testing.expect(!std.mem.eql(u8, &executor.binding_digest, &legacy.BINDING_DIGEST));
}

test "BLAKE3 statement AIR schedule covers every full-digest coordinate" {
    const inputs = bindings();
    var pp = try witness.Preprocessed.init(std.testing.allocator, 11, &inputs);
    defer pp.deinit();
    try pp.validate();
    var digest_rows: usize = 0;
    for (pp.rows) |row| {
        try std.testing.expectEqual(span.isIntegerWord(row.word_index), row.integer);
        if (!span.isDigestWord(row.word_index)) continue;
        digest_rows += 1;
        const main = try witness.mainRow(row, M31.fromCanonical(0xffff), .binary_node);
        try std.testing.expectEqual(M31.fromCanonical(255), main[2]);
        try std.testing.expectEqual(M31.fromCanonical(255), main[3]);
        try std.testing.expectError(error.IntegerWordOutOfRange, witness.mainRow(row, M31.fromCanonical(0x10000), .binary_node));
    }
    try std.testing.expectEqual(@as(usize, 4 * 14 * 16), digest_rows);
    pp.rows[span.canonical_layout.protocol_start].integer = false;
    try std.testing.expectError(error.AuthorityMismatch, pp.validate());
    try std.testing.expectError(error.InvalidInputBinding, witness.mainRow(pp.rows[span.canonical_layout.protocol_start], M31.zero(), .binary_node));
}

test "BLAKE3 statement AIR rejects legacy schedule and out-of-format coordinates" {
    var inputs = bindings();
    inputs[0].source.statement.index = span.SPAN_STATEMENT_CANONICAL_WORDS;
    try std.testing.expectError(error.InvalidInputBinding, witness.Preprocessed.init(std.testing.allocator, 11, &inputs));
    const old = [_]legacy.InputBinding{.{
        .node_id = 1,
        .use_count = 1,
        .source = .{ .statement = .{ .scope = 3, .index = 524, .active_kinds = .ALL } },
    }};
    try std.testing.expectError(error.InvalidInputBinding, legacy.Preprocessed.init(std.testing.allocator, 11, &old));
    // Even a common scalar coordinate has format-separated schedule authority.
    const old_common = [_]legacy.InputBinding{.{
        .node_id = 1,
        .use_count = 1,
        .source = .{ .statement = .{ .scope = 3, .index = 0, .active_kinds = .ALL } },
    }};
    const new_common = [_]witness.InputBinding{.{
        .node_id = 1,
        .use_count = 1,
        .source = .{ .statement = .{ .scope = 3, .index = 0, .active_kinds = .ALL } },
    }};
    var old_pp = try legacy.Preprocessed.init(std.testing.allocator, 11, &old_common);
    defer old_pp.deinit();
    var new_pp = try witness.Preprocessed.init(std.testing.allocator, 11, &new_common);
    defer new_pp.deinit();
    try std.testing.expect(!std.mem.eql(u8, &old_pp.authority_digest, &new_pp.authority_digest));
    new_pp.authority_digest = old_pp.authority_digest;
    try std.testing.expectError(error.AuthorityMismatch, new_pp.validate());
}

test "BLAKE3 statement AIR arithmetic rejects a forged digest decomposition" {
    const inputs = bindings();
    var pp = try witness.Preprocessed.init(std.testing.allocator, 11, &inputs);
    defer pp.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var logical = try witness.logicalRow(pp.rows[span.canonical_layout.protocol_start], M31.fromCanonical(0xffff), .binary_node);
    try expectConstraints(&definition, &logical, true);
    // Bypass the native witness validator, as a malicious prover can do.
    logical[1] = M31.fromCanonical(0x10000);
    try expectConstraints(&definition, &logical, false);
}

fn expectConstraints(definition: *const component.Definition, inputs: *const [component.LOGICAL_INPUT_COUNT]M31, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, inputs);
    defer std.testing.allocator.free(values);
    var satisfied = true;
    for (0..component.DIRECT_CONSTRAINT_COUNT) |i|
        satisfied = satisfied and support.constraintAt(&definition.arena, &definition.constraints, values, i).isZero();
    try std.testing.expectEqual(expected, satisfied);
}

test "BLAKE3 statement AIR writes final columns and rejects bad limbs before writes" {
    const inputs = bindings();
    var pp = try witness.Preprocessed.init(std.testing.allocator, 11, &inputs);
    defer pp.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(pp.log_size);
    const storage = try std.testing.allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    var values: [inputs.len]M31 = @splat(M31.fromCanonical(0xffff));
    try executor.generateMainInto(&pp, &columns, &values, .binary_node);
    for (pp.rows, values, 0..) |row, value, i| {
        const expected = try witness.mainRow(row, value, .binary_node);
        for (columns, expected) |column, word| try std.testing.expectEqual(word, column[i]);
    }
    for (columns) |column| for (column[values.len..]) |word| try std.testing.expect(word.isZero());
    // The last digest limb must be checked before any final-column mutation.
    values[values.len - 1] = M31.fromCanonical(0x10000);
    const sentinel = M31.fromCanonical(0x5151);
    @memset(storage, sentinel);
    try std.testing.expectError(error.IntegerWordOutOfRange, executor.generateMainInto(&pp, &columns, &values, .binary_node));
    for (storage) |word| try std.testing.expectEqual(sentinel, word);
    try std.testing.expectError(error.InvalidInputBinding, witness.logicalRowForEthereum(pp.rows[0], M31.zero(), .binary_node));
}
