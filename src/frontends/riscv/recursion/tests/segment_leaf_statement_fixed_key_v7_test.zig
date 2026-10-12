//! Regression: padded row-36 geometry does not determine its fixed columns.
//!
//! SegmentV2 has a 652-word fixed header followed by variable retained
//! sections. V7 therefore must not install the V6 Statement source's four
//! preprocessed columns from log geometry alone. A replacement AIR needs
//! proof-visible active/scope/index and fan-out multiplicity, constraints for
//! the canonical wire-then-context prefix, and exact links to verifier-owned
//! local/link consumers and the native authenticated statement values.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("../air/segment_leaf_statement_source_direct_v6.zig");
const native = @import("../segment_leaf_outer_air_v2.zig").Statement;
const boundary = @import("../segment_leaf_statement_contract_v2.zig");
const link = @import("../ethereum_leaf_link_program_v3.zig");
const child = @import("../ethereum_leaf_child_field_program_v1.zig");
const layout = @import("../segment_statement_v2_transcript_layout.zig");
const candidate = @import("../air/segment_leaf_statement_source_direct_v8.zig");
const types = @import("../../air/lang/types.zig");

test "row36 exact fixed columns differ for wire lengths with identical padded geometry" {
    const allocator = std.testing.allocator;
    const fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const empty = try layout.Layout.init(.{ 0, 0, 0, 0 });
    const retained = try layout.Layout.init(.{ 1, 0, 0, 0 });
    try std.testing.expectEqual(@as(usize, 664), empty.wordCount());
    try std.testing.expectEqual(@as(usize, 668), retained.wordCount());
    var program = try link.ProgramV3.init(allocator);
    defer program.deinit();
    var local = try child.ProgramV1.initWithNativeProgramBridge(allocator, &fixture.components, &fixture.infra);
    defer local.deinit();
    var first = try schedule(allocator, &program, &local, empty.wordCount(), 17);
    defer first.deinit();
    var same_shape_new_value = try schedule(allocator, &program, &local, empty.wordCount(), 23);
    defer same_shape_new_value.deinit();
    var longer = try schedule(allocator, &program, &local, retained.wordCount(), 17);
    defer longer.deinit();

    const first_capacity = try std.math.ceilPowerOfTwo(usize, first.rows.len);
    const longer_capacity = try std.math.ceilPowerOfTwo(usize, longer.rows.len);
    try std.testing.expectEqual(@as(usize, 1024), first_capacity);
    try std.testing.expectEqual(first_capacity, longer_capacity);
    try std.testing.expectEqualDeep(first.id, same_shape_new_value.id);
    try std.testing.expect(!first.rows[0][0].eql(same_shape_new_value.rows[0][0]));
    try std.testing.expect(!std.mem.eql(u8, &first.id, &longer.id));
    // At logical row 664, the first schedule starts the context; the second
    // still has a wire word. Their committed row is identical at log 10.
    try std.testing.expectEqual(boundary.CONTEXT_SCOPE, first.rows[empty.wordCount()][3].toU32());
    try std.testing.expectEqual(boundary.WIRE_SCOPE, longer.rows[empty.wordCount()][3].toU32());
}

fn schedule(
    allocator: std.mem.Allocator,
    program: *const link.ProgramV3,
    local: *const child.ProgramV1,
    wire_words: usize,
    value: u32,
) !air.Schedule {
    const old = try allocator.alloc(native.Row, wire_words + boundary.CONTEXT_WORD_COUNT);
    defer allocator.free(old);
    for (old, 0..) |*row, index| {
        const wire = index < wire_words;
        row.* = native.logicalRow(
            M31.fromCanonical(value),
            M31.one(),
            M31.fromCanonical(if (wire) boundary.WIRE_SCOPE else boundary.CONTEXT_SCOPE),
            M31.fromCanonical(@intCast(if (wire) index else index - wire_words)),
        );
    }
    return air.Schedule.init(allocator, program, local, old);
}

fn candidateSatisfied(definition: *const candidate.Definition, row: candidate.Row) !bool {
    const allocator = std.testing.allocator;
    const values = try @import("../air/test_support.zig").evaluateArena(allocator, &definition.arena, &row);
    defer allocator.free(values);
    for (definition.arena.constraintsView()) |constraint|
        if (!values[types.idIndex(constraint.root)].isZero()) return false;
    return true;
}

test "V8 Statement schedule uses identical fixed ordinals for 664 and 668 words" {
    try std.testing.expectEqualDeep(candidate.SEMANTIC_DIGEST, try candidate.computeSemanticDigest(std.testing.allocator));
    var definition = try candidate.build(std.testing.allocator);
    defer definition.deinit();
    const authenticated = try candidate.authenticate(&definition);
    var degrees = try @import("../../air/lang/degree.zig").analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(candidate.MAXIMUM_CONSTRAINT_DEGREE, degrees.maximumConstraintDegree());
    const fixed_a = try std.testing.allocator.alloc(M31, candidate.CAPACITY);
    defer std.testing.allocator.free(fixed_a);
    const fixed_b = try std.testing.allocator.alloc(M31, candidate.CAPACITY);
    defer std.testing.allocator.free(fixed_b);
    @memset(fixed_a, M31.zero());
    @memset(fixed_b, M31.zero());
    try candidate.writePreprocessed(fixed_a);
    try candidate.writePreprocessed(fixed_b);
    try std.testing.expectEqualSlices(M31, fixed_a, fixed_b);
    try std.testing.expectError(error.DirectStatementV8ColumnsNotFresh, candidate.writePreprocessed(fixed_a));
    try std.testing.expectEqual(@as(usize, 1), candidate.PREPROCESSED_COLUMN_COUNT);
    for ([_]u32{ 664, 668, candidate.MAX_WIRE_WORDS }) |count| {
        for (0..candidate.CAPACITY) |ordinal| {
            const active = ordinal < count + boundary.CONTEXT_WORD_COUNT;
            const row = try candidate.logicalRow(ordinal, count, if (active) M31.fromCanonical(17) else M31.zero(), 0);
            try std.testing.expectEqual(try candidate.fixedOrdinalRow(ordinal), row[candidate.PHYSICAL_MAIN_COLUMN_COUNT]);
            try std.testing.expect(try candidateSatisfied(&definition, row));
        }
    }
    const first = try candidate.logicalRow(664, 664, M31.fromCanonical(17), 0);
    const second = try candidate.logicalRow(664, 668, M31.fromCanonical(17), 0);
    try std.testing.expectEqual(first[candidate.PHYSICAL_MAIN_COLUMN_COUNT], second[candidate.PHYSICAL_MAIN_COLUMN_COUNT]);
    try std.testing.expect(!std.meta.eql(first, second));
    const first_event = authenticated.preparedEntries(first)[0];
    const second_event = authenticated.preparedEntries(second)[0];
    try std.testing.expectEqual(boundary.CONTEXT_SCOPE, (try first_event.values[0].tryIntoM31()).toU32());
    try std.testing.expectEqual(@as(u32, 0), (try first_event.values[1].tryIntoM31()).toU32());
    try std.testing.expectEqual(boundary.WIRE_SCOPE, (try second_event.values[0].tryIntoM31()).toU32());
    try std.testing.expectEqual(@as(u32, 664), (try second_event.values[1].tryIntoM31()).toU32());
}

test "V8 Statement rejects moved boundary, removed context, and forged fan-out" {
    var definition = try candidate.build(std.testing.allocator);
    defer definition.deinit();
    const value = M31.fromCanonical(17);
    var row = try candidate.logicalRow(664, 668, value, 0);
    row[1] = M31.zero();
    row[2] = M31.one();
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    row = try candidate.logicalRow(800, 664, value, 0);
    row[2] = M31.zero();
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    row = try candidate.logicalRow(900, 668, M31.zero(), 0);
    row[3] = M31.one();
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    row = try candidate.logicalRow(668, 668, value, 0);
    row[candidate.PHYSICAL_MAIN_COLUMN_COUNT + candidate.PREPROCESSED_COLUMN_COUNT] = M31.fromCanonical(664);
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    row = try candidate.logicalRow(7, 668, value, 0);
    row[candidate.PHYSICAL_MAIN_COLUMN_COUNT] = M31.fromCanonical(8);
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    row = try candidate.logicalRow(7, 668, value, 2);
    row[3] = M31.fromCanonical(3);
    try std.testing.expect(!try candidateSatisfied(&definition, row));
    try std.testing.expectError(error.InvalidDirectStatementV8Row, candidate.logicalRow(0, 888, value, 0));
    try std.testing.expectError(error.InvalidDirectStatementV8Row, candidate.logicalRow(0, 668, value, 3));
}

test "V8 Statement fan-out closes only against three authenticated consumers" {
    const allocator = std.testing.allocator;
    var definition = try candidate.build(allocator);
    defer definition.deinit();
    const plan = try candidate.authenticate(&definition);
    const relation = @import("../../air/lang/relation.zig");
    const interaction = @import("../air/relation_interaction.zig");
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const mask: u64 = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_statement_word);
    const value = M31.fromCanonical(17);
    const row = try candidate.logicalRow(7, 668, value, 2);
    try std.testing.expect(try candidateSatisfied(&definition, row));
    const tuple = [_]QM31{ .fromBase(M31.fromCanonical(boundary.WIRE_SCOPE)), .fromBase(M31.fromCanonical(7)), .fromBase(value) };
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 36, &.{row}, mask);
    inline for ([_]u8{ 11, 40, 47 }) |component|
        try ledger.append(.recursion_statement_word, component, 0, .consume, QM31.one().neg(), &tuple);
    try std.testing.expect(ledger.classify().isClosed());

    var short = interaction.TupleLedger.init(allocator);
    defer short.deinit();
    const missing = try candidate.logicalRow(7, 668, value, 1);
    try short.append(.recursion_statement_word, 11, 0, .consume, QM31.one().neg(), &tuple);
    try short.append(.recursion_statement_word, 40, 0, .consume, QM31.one().neg(), &tuple);
    try short.append(.recursion_statement_word, 47, 0, .consume, QM31.one().neg(), &tuple);
    try plan.appendPreparedTupleContributions(&short, 36, &.{missing}, mask);
    try std.testing.expectEqual(@as(usize, 1), short.classify().unmatched_by_domain[29]);
}
