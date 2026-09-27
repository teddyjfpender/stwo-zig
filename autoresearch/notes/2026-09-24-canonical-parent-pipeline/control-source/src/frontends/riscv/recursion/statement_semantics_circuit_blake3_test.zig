const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const circuit_mod = @import("statement_semantics_circuit_blake3.zig");
const legacy = @import("statement_semantics_circuit.zig");
const row11 = @import("air/statement_semantics_input_witness_blake3.zig");
const span = @import("span_statement_blake3.zig");
const fixture = @import("span_statement_blake3_test_fixture.zig");

test "BLAKE3 statement circuit has sealed geometry and matching input authority" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    try circuit.validate();
    try std.testing.expectEqual(@as(usize, 4 * 525), circuit_mod.STATEMENT_INPUT_COUNT);
    try std.testing.expectEqual(circuit_mod.NODE_COUNT, circuit.nodeCount());
    try std.testing.expectEqual(circuit_mod.OUTPUT_COUNT, circuit.outputCount());
    try std.testing.expect(!std.mem.eql(u8, &circuit.identity_digest, &legacy.IDENTITY_DIGEST));
    var pp = try row11.Preprocessed.init(std.testing.allocator, 11, circuit.inputBindings());
    defer pp.deinit();
    try pp.validate();
    var digests: usize = 0;
    for (pp.rows) |row| if (row.source == .statement and span.isDigestWord(row.word_index)) {
        try std.testing.expect(row.integer);
        digests += 1;
    };
    try std.testing.expectEqual(@as(usize, 4 * 14 * 16), digests);
    circuit.identity_digest = legacy.IDENTITY_DIGEST;
    try std.testing.expectError(error.CircuitIdentityMismatch, circuit.validate());
}

test "BLAKE3 statement circuit binds every continuation and edge digest limb" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);
    const context = try fixture.job(2);
    const middle = try fixture.state(8, 0xa0);
    const a = try fixture.leaf(context, 0, context.complete.initial_state, middle);
    const b = try fixture.leaf(context, 1, middle, context.complete.final_state);
    const parent = try (try span.SpanStatement.fold(a, b)).canonicalWords();
    const left = try a.canonicalWords();
    const right = try b.canonicalWords();
    try circuit.evaluateInto(circuit_mod.Witness.forBinary(&left, &right, &parent), inputs, values);
    const layout = span.canonical_layout;
    for ([_]usize{
        layout.entry_state_start + layout.machine_state_rw_digest_start_offset,
        layout.entry_state_start + layout.machine_state_io_digest_start_offset,
        layout.input_edge_digest_start,
        layout.output_edge_digest_start,
    }) |start| {
        for (0..span.DIGEST_WORD_COUNT) |limb| {
            var changed_left = left;
            var changed_right = right;
            const changed = if (start == layout.input_edge_digest_start) &changed_left else &changed_right;
            changed[start + limb] = changed[start + limb].add(M31.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateIntoAssumeValid(
                circuit_mod.Witness.forBinary(&changed_left, &changed_right, &parent),
                inputs,
                values,
            ));
        }
    }
}

test "BLAKE3 statement circuit enforces version and validates range through input AIR" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const context = try fixture.job(1);
    const statement = try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state);
    var words = try statement.canonicalWords();
    var evaluation = try circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forSegment(&words));
    defer evaluation.deinit();
    var pp = try row11.Preprocessed.init(std.testing.allocator, 11, circuit.inputBindings());
    defer pp.deinit();
    for (pp.rows, evaluation.inputs()) |row, value| {
        _ = try row11.logicalRow(row, value.toM31Array()[0], .segment_leaf);
    }
    words[1] = M31.fromCanonical(2);
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forSegment(&words)));
    words = try statement.canonicalWords();
    // A common job identity has no arithmetic interpretation in the fold graph;
    // its u16 admission must come from the authenticated input AIR schedule.
    words[span.canonical_layout.protocol_start] = M31.fromCanonical(0x10000);
    var invalid = try circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forSegment(&words));
    defer invalid.deinit();
    var rejected = false;
    for (pp.rows, invalid.inputs()) |row, value| {
        _ = row11.logicalRow(row, value.toM31Array()[0], .segment_leaf) catch |err| {
            try std.testing.expectEqual(error.IntegerWordOutOfRange, err);
            rejected = true;
            continue;
        };
    }
    try std.testing.expect(rejected);
}

test "BLAKE3 statement circuit covers padded folds and empty subtrees" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const context = try fixture.job(3);
    const last = try fixture.leaf(context, 2, try fixture.state(8, 0xa0), context.complete.final_state);
    const padding = try span.SpanStatement.emptyLeaf(context, 3);
    const parent = try span.SpanStatement.fold(last, padding);
    const left_words = try last.canonicalWords();
    const right_words = try padding.canonicalWords();
    const parent_words = try parent.canonicalWords();
    var evaluation = try circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forBinary(&left_words, &right_words, &parent_words));
    defer evaluation.deinit();
    const empty_context = try fixture.job(5);
    const empty_left = try span.SpanStatement.emptyLeaf(empty_context, 6);
    const empty_right = try span.SpanStatement.emptyLeaf(empty_context, 7);
    const empty_parent = try span.SpanStatement.fold(empty_left, empty_right);
    const a = try empty_left.canonicalWords();
    const b = try empty_right.canonicalWords();
    const c = try empty_parent.canonicalWords();
    var empty_leaf = try circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forEmpty(&a));
    defer empty_leaf.deinit();
    var empty_fold = try circuit.evaluate(std.testing.allocator, circuit_mod.Witness.forBinary(&a, &b, &c));
    defer empty_fold.deinit();
}
