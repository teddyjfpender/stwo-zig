const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").recursion.air;
const Air = air.fixed_wire_v3;
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Binding = air.universal_relation_binding.Binding(Air);
const Ledger = air.relation_interaction.TupleLedger;

pub fn exercise() !void {
    const allocator = std.testing.allocator;
    const identity = try Air.computeSemanticDigest(allocator);
    std.debug.print("FIXED_WIRE_AIR_DIGEST={s}\n", .{std.fmt.bytesToHex(identity, .lower)});
    try std.testing.expectEqualDeep(Air.SEMANTIC_DIGEST, identity);
    try exerciseZeroPolicy();
    const terms = [_]air.verifier_arithmetic_lowering.PublicWireTerm{
        .{ .lane = 0, .active_in = .binary, .role = .emit, .circuit_id = 7, .node_id = 19, .value = QM31.fromU32Unchecked(3, 5, 7, 11), .multiplicity = 13 },
        .{ .lane = 0, .active_in = .binary, .role = .consume, .circuit_id = 7, .node_id = 23, .value = QM31.zero(), .multiplicity = 1 },
    };
    var rows = [_]Air.Row{ try Air.logicalRow(terms[0]), try Air.logicalRow(terms[1]) };
    try check(&rows, &terms);
    rows[0][0] = M31.zero();
    try std.testing.expectError(error.FixedWireConstraintMismatch, check(&rows, &terms));
    rows[0] = try Air.logicalRow(terms[0]);
    // A missing constant, changed extension-field coordinate or wrong use
    // count must not close against the authenticated arithmetic graph.
    try std.testing.expectError(error.FixedWireTupleMismatch, check(rows[1..], &terms));
    for ([_]usize{ 4, 5, 6, 7, 8 }) |column| {
        const original = rows[0][column];
        rows[0][column] = original.add(M31.one());
        try std.testing.expectError(error.FixedWireTupleMismatch, check(&rows, &terms));
        rows[0][column] = original;
    }
    var invalid = terms[0];
    invalid.role = .request;
    try std.testing.expectError(error.InvalidFixedWireTerm, Air.logicalRow(invalid));
    invalid = terms[0];
    invalid.multiplicity = 0;
    try std.testing.expectError(error.InvalidFixedWireTerm, Air.logicalRow(invalid));
    std.debug.print("FIXED_WIRE_AIR anchors=2 signed_multiplicity=true missing_or_changed_anchor_rejected=true\n", .{});
}

fn check(rows: []const Air.Row, terms: []const air.verifier_arithmetic_lowering.PublicWireTerm) !void {
    const allocator = std.testing.allocator;
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const direct = air.direct_constraint_program;
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try Binding.authenticate(&definition);
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try compiled.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero()) return error.FixedWireConstraintMismatch;
        for (plan.preparedEntries(row)) |entry| try ledger.append(entry.domain, 10, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
    for (terms) |term| {
        if (term.active_in != .binary) continue;
        var weight = QM31.fromBase(M31.fromCanonical(term.multiplicity));
        if (term.role == .emit) weight = weight.neg();
        const limbs = term.value.toM31Array();
        const tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(term.circuit_id)), QM31.fromBase(M31.fromCanonical(term.node_id)), QM31.fromBase(limbs[0]), QM31.fromBase(limbs[1]), QM31.fromBase(limbs[2]), QM31.fromBase(limbs[3]) };
        try ledger.append(.recursion_wire, 31, 0, if (term.role == .emit) .consume else .emit, weight, &tuple);
    }
    if (!ledger.classify().isClosed()) return error.FixedWireTupleMismatch;
}

/// Check the actual captured child graphs, including owner mutation rejection.
pub fn exerciseCaptured(prepared: anytype, source: anytype) !void {
    const plan = &source.arithmetic_rows.?.plan;
    try prepared.validateFixedWires(plan, source.arithmetic_rows.?.reference);
    try exerciseCapturedZeros(prepared, source);
    const rows = @constCast(prepared.logical[11]);
    try std.testing.expect(rows.len > 0);
    var wire_count: usize = 0;
    for (plan.public_terms) |term| if (term.active_in == .binary) {
        wire_count += 1;
    };
    try check(rows[0..wire_count], plan.public_terms);
    try std.testing.expectError(error.FixedWireTupleMismatch, check(rows[1..wire_count], plan.public_terms));
    const original = rows[0][4];
    rows[0][4] = original.add(M31.one());
    defer rows[0][4] = original;
    try std.testing.expectError(error.FixedWireTupleMismatch, check(rows[0..wire_count], plan.public_terms));
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, prepared.validateFixedWires(plan, source.arithmetic_rows.?.reference));
    std.debug.print("COMMON_FOLD_FIXED_WIRES rows={d} graph_join=true missing_or_changed_anchor_rejected=true\n", .{rows.len});
}

fn exerciseZeroPolicy() !void {
    const Prepared = @import("recursive_secure_transcript_rows_v1.zig").Prepared;
    for (36..39) |item| {
        try std.testing.expect(Prepared.isFixedZeroInput(.canonical_empty, @intCast(item)));
        try std.testing.expect(Prepared.isFixedZeroInput(.common_fold, @intCast(item)));
    }
    for ([_]u32{ 0, 35, 39, 40, 42 }) |item| {
        try std.testing.expect(!Prepared.isFixedZeroInput(.canonical_empty, item));
        try std.testing.expect(!Prepared.isFixedZeroInput(.common_fold, item));
    }
    try std.testing.expect(!Prepared.isFixedZeroInput(.canonical_empty, 41));
    try std.testing.expect(Prepared.isFixedZeroInput(.common_fold, 41));
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try Binding.authenticate(&definition);
    const row = try Air.zeroVerifierInputRow(2, 41, 3);
    const entries = plan.preparedEntries(row);
    try std.testing.expect(entries[0].numerator.isZero());
    try std.testing.expectEqual(.recursion_verifier_input_word, entries[1].domain);
    try std.testing.expect(entries[1].numerator.eql(QM31.one()));
    for (entries[1].values[0..5], [_]u32{ 2, 5, 41, 3, 0 }) |actual, expected|
        try std.testing.expect(actual.eql(QM31.fromBase(M31.fromCanonical(expected))));
}

fn exerciseCapturedZeros(prepared: anytype, source: anytype) !void {
    const checks = @import("recursive_secure_transcript_rows_v1_test.zig");
    const composition = source.composition_rows.?;
    var count: usize = 0;
    for (composition.input_preprocessing.rows, 0..) |row, index| {
        const input = switch (row.classification) {
            .recursion_input => |input| input,
            else => continue,
        };
        if (input.source != .claimed_sum) continue;
        const item = input.source.claimed_sum.item_index;
        if (item < 36 or item >= 39) continue;
        count += 1;
        try std.testing.expect(composition.schedule_values[index].isZero());
        if (count == 1) {
            const original = composition.schedule_values[index];
            @constCast(composition.schedule_values)[index] = M31.one();
            defer @constCast(composition.schedule_values)[index] = original;
            try std.testing.expectError(error.RecursiveTranscriptSemanticJoinMismatch, checks.validateSemanticJoin(prepared, source));
        }
    }
    try std.testing.expectEqual(@as(usize, 24), count);
    const rows = @constCast(prepared.logical[11]);
    const last = &rows[rows.len - 1];
    const original = last[9];
    last[9] = M31.zero();
    defer last[9] = original;
    try std.testing.expectError(error.RecursiveTranscriptSemanticJoinMismatch, checks.validateSemanticJoin(prepared, source));
    std.debug.print("COMMON_FOLD_ZERO_VERIFIER_INPUTS limbs=24 air_join=true changed_consumer_or_missing_producer_rejected=true\n", .{});
}
