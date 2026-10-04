const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const witness = @import("../vm_air_composition_input_witness_blake3.zig");
const component = @import("../vm_air_composition_input.zig");
const interaction = @import("../vm_air_composition_input_relation.zig");
const compiler = @import("../composition_circuit_blake3.zig");
const provider = @import("../statement_input_witness_blake3.zig");
const provider_component = @import("../statement_input.zig");
const provider_relation = @import("../statement_input_relation.zig");
const semantics = @import("../statement_semantics_input_witness_blake3.zig");
const semantics_component = @import("../statement_semantics_input.zig");
const semantics_relation = @import("../statement_semantics_input_relation.zig");
const graph = @import("../../statement_semantics_circuit_blake3.zig");
const fixture = @import("../../span_statement_blake3_test_fixture.zig");
const span = @import("../../span_statement_blake3.zig");

test "BLAKE3 composition witness has a pinned format-specific binding" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(witness.BINDING_DIGEST_HEX, &std.fmt.bytesToHex(binding.identityDigest(), .lower));
    _ = try witness.Executor.init(&definition, &binding);
}

/// Called with the authenticated reference from the schedule-compiler fixture.
pub fn qualifyCompiled(reference: *const compiler.Reference) !void {
    var pp = try witness.Preprocessed.initFromReference(std.testing.allocator, reference);
    defer pp.deinit();
    try std.testing.expectEqual(witness.Preprocessed.Source.authenticated_graph, pp.source);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(pp.log_size);
    const storage = try std.testing.allocator.alloc(M31, 2 * size);
    defer std.testing.allocator.free(storage);
    var columns = [2][]M31{ storage[0..size], storage[size..] };
    const values = try std.testing.allocator.alloc(M31, pp.rows.len);
    defer std.testing.allocator.free(values);
    for (pp.rows, values) |row, *value| value.* = switch (row.classification) {
        .recursion_input => |input| switch (input.source) {
            .parent_binary_selector => M31.one(),
            .child_kind_selector => |kind| M31.fromCanonical(@intFromBool(kind == .segment_leaf)),
            else => M31.fromCanonical(0xffff),
        },
        else => M31.zero(),
    };
    try executor.generateMainInto(&pp, &columns, values, .binary_node);
    for (values, 0..) |value, i| try std.testing.expectEqual(value, columns[1][i]);
    for (columns) |column| for (column[pp.rows.len..]) |value| try std.testing.expect(value.isZero());
    @memset(storage, M31.one());
    pp.authority_digest[0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, executor.generateMainInto(&pp, &columns, values, .binary_node));
    for (storage) |value| try std.testing.expectEqual(M31.one(), value);
}

test "BLAKE3 composition witness closes both consumers of every binary child word" {
    var pp = try provider.Preprocessed.init(std.testing.allocator);
    defer pp.deinit();
    var circuit = try graph.build(std.testing.allocator);
    defer circuit.deinit();
    var semantic_pp = try semantics.Preprocessed.init(std.testing.allocator, 11, circuit.inputBindings());
    defer semantic_pp.deinit();
    var source = try provider_component.build(std.testing.allocator);
    defer source.deinit();
    var fold = try semantics_component.build(std.testing.allocator);
    defer fold.deinit();
    var composition = try component.build(std.testing.allocator);
    defer composition.deinit();
    const emit = try provider_relation.authenticate(&source);
    const consume_fold = try semantics_relation.authenticate(&fold);
    const consume_composition = try interaction.authenticate(&composition);
    const context = try fixture.job(2);
    const middle = try fixture.state(8, 0xa0);
    const a = try fixture.leaf(context, 0, context.complete.initial_state, middle);
    const b = try fixture.leaf(context, 1, middle, context.complete.final_state);
    const left = try a.canonicalWords();
    const right = try b.canonicalWords();
    const parent = try (try span.SpanStatement.fold(a, b)).canonicalWords();
    const input = provider.StatementWitness{ .binary_node = .{ .left = &left, .right = &right, .parent = &parent } };
    var checked: usize = 0;
    for (semantic_pp.rows) |row| {
        if (row.source != .statement or (row.statement_scope != 1 and row.statement_scope != 2)) continue;
        const words = if (row.statement_scope == 1) &left else &right;
        const value = words[row.word_index];
        const producer = try emit.entries(&source.arena, provider_component.SEMANTIC_DIGEST, source.events.ordered(), try provider.logicalRow(pp.rows[row.statement_scope * 525 + row.word_index], input));
        const first = try consume_fold.entries(&fold.arena, semantics_component.SEMANTIC_DIGEST, fold.events.ordered(), try semantics.logicalRow(row, value, .binary_node));
        const composition_row = witness.Row{
            .circuit_id = 20 + row.statement_scope,
            .node_id = 4 + row.word_index,
            .use_count = 1,
            .classification = .{ .recursion_input = .{ .verifier_id = row.statement_scope, .statement_scope = row.statement_scope, .source = .{ .statement_word = row.word_index } } },
        };
        const second = try consume_composition.entries(&composition.arena, component.SEMANTIC_DIGEST, composition.events, try witness.logicalRow(composition_row, value, .binary_node));
        const emitted = producer[1];
        inline for (.{ first[0], second[6] }) |consumed| {
            try std.testing.expectEqual(emitted.domain, consumed.domain);
            try std.testing.expectEqual(emitted.arity, consumed.arity);
            for (emitted.values, consumed.values) |x, y| try std.testing.expect(x.eql(y));
        }
        try std.testing.expect(emitted.numerator.add(first[0].numerator).add(second[6].numerator).isZero());
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 1050), checked);
}
