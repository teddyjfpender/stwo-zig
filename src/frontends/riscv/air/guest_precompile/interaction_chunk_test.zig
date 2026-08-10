//! BatchPlan-offset and cache-chunk rollover evidence for C-008.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const logup = @import("../logup.zig");
const components = @import("component_registry.zig");
const subject = @import("interaction.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const relation_challenges = @import("relation_challenges.zig");
const registry = @import("relation_registry.zig");
const statement_mod = @import("statement.zig");

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn callerSecureRow(
    main: *const main_trace.Result,
    row: usize,
) [main_trace.caller_main_column_count]QM31 {
    var result: [main_trace.caller_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(main.callerMain(column)[row]);
    }
    return result;
}

fn providerSecureRow(
    main: *const main_trace.Result,
    row: usize,
) [main_trace.provider_main_column_count]QM31 {
    var result: [main_trace.provider_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(main.providerMain(column)[row]);
    }
    return result;
}

fn callerSums(
    interaction: *const subject.Result,
    row: usize,
) [subject.caller_batch_count]QM31 {
    var result: [subject.caller_batch_count]QM31 = undefined;
    for (components.caller_batches) |batch| {
        const start: usize = batch.interaction_column_start;
        result[batch.ordinal] = QM31.fromM31Array(.{
            interaction.callerColumn(start)[row],
            interaction.callerColumn(start + 1)[row],
            interaction.callerColumn(start + 2)[row],
            interaction.callerColumn(start + 3)[row],
        });
    }
    return result;
}

fn providerSums(
    interaction: *const subject.Result,
    row: usize,
) [subject.provider_batch_count]QM31 {
    var result: [subject.provider_batch_count]QM31 = undefined;
    for (components.provider_batches) |batch| {
        const start: usize = batch.interaction_column_start;
        result[batch.ordinal] = QM31.fromM31Array(.{
            interaction.providerColumn(start)[row],
            interaction.providerColumn(start + 1)[row],
            interaction.providerColumn(start + 2)[row],
            interaction.providerColumn(start + 3)[row],
        });
    }
    return result;
}

fn pairTerm(pair: logup.RowPair) !QM31 {
    var result = QM31.zero();
    if (!pair.n1.isZero()) result = result.add(pair.n1.mul(
        pair.d1.inv() catch return error.ZeroDenominator,
    ));
    if (!pair.n2.isZero()) result = result.add(pair.n2.mul(
        pair.d2.inv() catch return error.ZeroDenominator,
    ));
    return result;
}

fn expectAllZero(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

test "interaction entries validate schema and arity before accepting zero" {
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var entry = subject.Entry{
        .schema = @enumFromInt(999),
        .role = .request,
        .access_ordinal = null,
        .numerator = QM31.one(),
        .values = undefined,
        .arity = 0,
    };
    try std.testing.expectError(
        error.UnknownRelationSchema,
        entry.denominator(&relations),
    );
    entry.schema = registry.guest_schema_id;
    entry.arity = 31;
    try std.testing.expectError(
        error.InvalidEntryArity,
        entry.denominator(&relations),
    );
    entry.numerator = QM31.zero();
    entry.schema = @enumFromInt(999);
    entry.arity = 0;
    try std.testing.expectError(
        error.UnknownRelationSchema,
        entry.term(&relations),
    );
    entry.schema = registry.guest_schema_id;
    entry.arity = 31;
    try std.testing.expectError(
        error.InvalidEntryArity,
        entry.term(&relations),
    );
}

test "interaction authenticated BatchPlan offsets own and carry every cumulative column" {
    var occupied = [_]bool{false} ** subject.total_column_count;
    for (components.caller_batches, 0..) |batch, index| {
        try std.testing.expectEqual(index, batch.ordinal);
        const start: usize = batch.interaction_column_start;
        try std.testing.expect(start + 4 <= subject.caller_column_count);
        for (start..start + 4) |column| {
            try std.testing.expect(!occupied[column]);
            occupied[column] = true;
        }
    }
    for (components.provider_batches, 0..) |batch, index| {
        try std.testing.expectEqual(index, batch.ordinal);
        const start = subject.caller_column_count +
            @as(usize, batch.interaction_column_start);
        try std.testing.expect(start + 4 <= subject.total_column_count);
        for (start..start + 4) |column| {
            try std.testing.expect(!occupied[column]);
            occupied[column] = true;
        }
    }
    for (occupied) |is_owned| try std.testing.expect(is_owned);

    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var interaction = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();

    var caller_expected = [_]QM31{QM31.zero()} ** subject.caller_batch_count;
    var provider_expected = [_]QM31{QM31.zero()} ** subject.provider_batch_count;
    for (0..interaction.n_rows) |logical_row| {
        const row = main_trace.committedRow(logical_row, interaction.log_size);
        const caller_pairs = try subject.callerRowPairs(
            &callerSecureRow(&main, row),
            &relations,
        );
        const caller_actual = callerSums(&interaction, row);
        for (components.caller_batches) |batch| {
            caller_expected[batch.ordinal] = caller_expected[batch.ordinal].add(
                try pairTerm(caller_pairs[batch.ordinal]),
            );
            try std.testing.expect(caller_expected[batch.ordinal].eql(
                caller_actual[batch.ordinal],
            ));
        }
        const provider_pairs = try subject.providerRowPairs(
            &providerSecureRow(&main, row),
            &relations,
        );
        const provider_actual = providerSums(&interaction, row);
        for (components.provider_batches) |batch| {
            provider_expected[batch.ordinal] = provider_expected[batch.ordinal].add(
                try pairTerm(provider_pairs[batch.ordinal]),
            );
            try std.testing.expect(provider_expected[batch.ordinal].eql(
                provider_actual[batch.ordinal],
            ));
        }
    }
    for (components.caller_batches) |batch| try std.testing.expect(
        caller_expected[batch.ordinal].eql(interaction.caller_claims[batch.ordinal]),
    );
    for (components.provider_batches) |batch| try std.testing.expect(
        provider_expected[batch.ordinal].eql(interaction.provider_claims[batch.ordinal]),
    );
}

test "interaction prefix and constraints cross the 256-row chunk boundary exactly" {
    const row_count: u32 = @intCast(subject.chunk_rows + 1);
    var core = support.coreFixture(row_count);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, row_count);
    var logs = try support.logsFixture(std.testing.allocator, row_count);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var interaction = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();

    try std.testing.expectEqual(@as(usize, 512), interaction.domainSize());
    const before = main_trace.committedRow(subject.chunk_rows - 1, interaction.log_size);
    const rollover = main_trace.committedRow(subject.chunk_rows, interaction.log_size);
    const padding = main_trace.committedRow(subject.chunk_rows + 1, interaction.log_size);
    const caller_before = callerSums(&interaction, before);
    const caller_rollover = callerSums(&interaction, rollover);
    const provider_before = providerSums(&interaction, before);
    const provider_rollover = providerSums(&interaction, rollover);

    const caller_pairs = try subject.callerRowPairs(
        &callerSecureRow(&main, rollover),
        &relations,
    );
    for (components.caller_batches) |batch| {
        const expected = caller_before[batch.ordinal].add(
            try pairTerm(caller_pairs[batch.ordinal]),
        );
        try std.testing.expect(expected.eql(caller_rollover[batch.ordinal]));
    }
    const provider_pairs = try subject.providerRowPairs(
        &providerSecureRow(&main, rollover),
        &relations,
    );
    for (components.provider_batches) |batch| {
        const expected = provider_before[batch.ordinal].add(
            try pairTerm(provider_pairs[batch.ordinal]),
        );
        try std.testing.expect(expected.eql(provider_rollover[batch.ordinal]));
    }
    try std.testing.expect(!caller_before[subject.caller_batch_count - 1].eql(
        caller_rollover[subject.caller_batch_count - 1],
    ));

    try expectAllZero(try subject.callerInteractionConstraints(
        &callerSecureRow(&main, rollover),
        QM31.zero(),
        caller_rollover,
        caller_before,
        interaction.caller_claims,
        &relations,
    ));
    try expectAllZero(try subject.providerInteractionConstraints(
        &providerSecureRow(&main, rollover),
        QM31.zero(),
        provider_rollover,
        provider_before,
        interaction.provider_claims,
        &relations,
    ));
    for (callerSums(&interaction, padding), interaction.caller_claims) |actual, claim| {
        try std.testing.expect(actual.eql(claim));
    }
    for (providerSums(&interaction, padding), interaction.provider_claims) |actual, claim| {
        try std.testing.expect(actual.eql(claim));
    }
    try interaction.verifyGuestCancellation();
}

comptime {
    if (subject.caller_event_count != 153 or subject.caller_batch_count != 77 or
        subject.provider_event_count != 4 or subject.provider_batch_count != 2 or
        subject.chunk_rows != 256 or subject.total_column_count != 316)
    {
        @compileError("C-008 chunk or interaction geometry drifted");
    }
}
