const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const provider = @import("../statement_input_witness_blake3.zig");
const legacy = @import("../statement_input_witness.zig");
const consumer = @import("../statement_semantics_input_witness_blake3.zig");
const component = @import("../statement_input.zig");
const consumer_component = @import("../statement_semantics_input.zig");
const relation = @import("../../../air/lang/relation.zig");
const provider_relation = @import("../statement_input_relation.zig");
const consumer_relation = @import("../statement_semantics_input_relation.zig");
const graph = @import("../../statement_semantics_circuit_blake3.zig");
const span = @import("../../span_statement_blake3.zig");
const fixture = @import("../../span_statement_blake3_test_fixture.zig");

test "BLAKE3 statement provider pins its binding and full schedule" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try provider.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(provider.BINDING_DIGEST_HEX, &std.fmt.bytesToHex(binding.identityDigest(), .lower));
    _ = try provider.Executor.init(&definition, &binding);
    var pp = try provider.Preprocessed.init(std.testing.allocator);
    defer pp.deinit();
    try pp.validate();
    try std.testing.expectEqual(@as(usize, 2100), pp.rows.len);
    try std.testing.expectEqual(@as(usize, 525), pp.activeWordCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 1575), pp.activeWordCount(.binary_node));
    var old_pp = try legacy.Preprocessed.init(std.testing.allocator);
    defer old_pp.deinit();
    pp.authority_digest = old_pp.authority_digest;
    try std.testing.expectError(error.AuthorityMismatch, pp.validate());
}

test "BLAKE3 statement provider closes all segment and parent graph input tuples" {
    var pp = try provider.Preprocessed.init(std.testing.allocator);
    defer pp.deinit();
    var circuit = try graph.build(std.testing.allocator);
    defer circuit.deinit();
    var inputs = try consumer.Preprocessed.init(std.testing.allocator, 11, circuit.inputBindings());
    defer inputs.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var input_definition = try consumer_component.build(std.testing.allocator);
    defer input_definition.deinit();
    const emit = try provider_relation.authenticate(&definition);
    const consume = try consumer_relation.authenticate(&input_definition);
    const context = try fixture.job(1);
    const statement = try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state);
    const words = try statement.canonicalWords();
    const witness = provider.StatementWitness{ .segment_leaf = &words };
    var checked: usize = 0;
    for (inputs.rows) |row| {
        if (row.source != .statement or !row.active_kinds.contains(.segment_leaf)) continue;
        const produced = try emit.entries(&definition.arena, component.SEMANTIC_DIGEST, definition.events.ordered(), try provider.logicalRow(pp.rows[row.word_index], witness));
        const consumed = try consume.entries(&input_definition.arena, consumer_component.SEMANTIC_DIGEST, input_definition.events.ordered(), try consumer.logicalRow(row, words[row.word_index], .segment_leaf));
        const source = produced[if (row.statement_scope == component.PARENT_STATEMENT_SCOPE) @as(usize, 2) else 1];
        const target = consumed[0];
        try std.testing.expectEqual(relation.Domain.recursion_statement_word, source.domain);
        try std.testing.expectEqual(source.domain, target.domain);
        try std.testing.expectEqual(source.arity, target.arity);
        try std.testing.expect(source.numerator.add(target.numerator).isZero());
        for (source.values, target.values) |a, b| try std.testing.expect(a.eql(b));
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 1050), checked);
}

test "BLAKE3 statement provider writes all binary words and fails before mutation" {
    var pp = try provider.Preprocessed.init(std.testing.allocator);
    defer pp.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try provider.Binding.canonical(&definition);
    const executor = try provider.Executor.init(&definition, &binding);
    const context = try fixture.job(2);
    const middle = try fixture.state(8, 0xa0);
    const a = try fixture.leaf(context, 0, context.complete.initial_state, middle);
    const b = try fixture.leaf(context, 1, middle, context.complete.final_state);
    const left = try a.canonicalWords();
    const right = try b.canonicalWords();
    const parent = try (try span.SpanStatement.fold(a, b)).canonicalWords();
    const witness = provider.StatementWitness{ .binary_node = .{ .left = &left, .right = &right, .parent = &parent } };
    const size = @as(usize, 1) << @intCast(pp.log_size);
    const storage = try std.testing.allocator.alloc(M31, 2 * size);
    defer std.testing.allocator.free(storage);
    var columns = [2][]M31{ storage[0..size], storage[size..] };
    try executor.generateMainInto(&pp, &columns, witness);
    for (0..525) |i| {
        try std.testing.expect(columns[1][i].isZero());
        try std.testing.expectEqual(left[i], columns[1][525 + i]);
        try std.testing.expectEqual(right[i], columns[1][1050 + i]);
        try std.testing.expectEqual(parent[i], columns[1][1575 + i]);
    }
    for (columns) |column| for (column[pp.rows.len..]) |value| try std.testing.expect(value.isZero());
    @memset(storage, M31.one());
    pp.rows[pp.rows.len - 1].word_index = 525;
    try std.testing.expectError(error.AuthorityMismatch, executor.generateMainInto(&pp, &columns, witness));
    for (storage) |value| try std.testing.expectEqual(M31.one(), value);
}
