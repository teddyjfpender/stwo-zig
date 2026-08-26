const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const challenges = @import("../relation_challenges.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const compat = @import("typed_poseidon2_compat.zig");
const materializer = @import("degree3_materializer.zig");
const ir = @import("ir.zig");
const poseidon = @import("typed_poseidon2.zig");
const relations = @import("typed_poseidon2_relations.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "Poseidon2 typed relation plan authenticates schemas batches and H-004 binding" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const authority = fixture.authority();
    try fixture.relation_plan.validateAgainst(std.testing.allocator, authority);

    try std.testing.expectEqualDeep(
        relations.Identity.canonical(),
        fixture.relation_plan.identity,
    );
    try std.testing.expectEqualDeep(compat.Identity.canonical(), fixture.relation_plan.compatibility_identity);
    try std.testing.expectEqualSlices(u8, &.{ 16, 1, 8, 32 }, &.{
        fixture.relation_plan.events[0].semantic_width,
        fixture.relation_plan.events[1].semantic_width,
        fixture.relation_plan.events[2].semantic_width,
        fixture.relation_plan.events[3].semantic_width,
    });
    for (fixture.relation_plan.events) |event| {
        try std.testing.expectEqual(@as(u8, @intCast(@intFromEnum(event.id))), event.ordinal);
        try std.testing.expectEqual(
            @as(u8, if (event.domain == .poseidon2_io) 32 else 16),
            event.relation_arity,
        );
        try std.testing.expectEqual(@as(?u8, null), event.access_ordinal);
        try std.testing.expectEqual(@import("relation.zig").Role.request, event.role);
    }
    try std.testing.expectEqual(relations.EventId.input, fixture.relation_plan.batches[0].first);
    try std.testing.expectEqual(relations.EventId.narrow_output, fixture.relation_plan.batches[0].second);
    try std.testing.expectEqual(relations.EventId.wide_output, fixture.relation_plan.batches[1].first);
    try std.testing.expectEqual(relations.EventId.io, fixture.relation_plan.batches[1].second);
    try std.testing.expectEqual(@as(u8, 4), fixture.relation_plan.batches[1].interaction_column_start);
    try std.testing.expectError(
        error.EventPlanMismatch,
        fixture.relation_plan.events[0].validate(relations.N_EVENTS),
    );
    try std.testing.expectError(
        error.BatchPlanMismatch,
        fixture.relation_plan.batches[0].validate(relations.N_BATCHES),
    );

    var forged_plan = fixture.relation_plan;
    forged_plan.events[1].numerator = .enabled_wide;
    try std.testing.expectError(
        error.EventPlanMismatch,
        forged_plan.validateAgainst(std.testing.allocator, authority),
    );
    forged_plan = fixture.relation_plan;
    forged_plan.batches[0].second = .io;
    try std.testing.expectError(
        error.BatchPlanMismatch,
        forged_plan.validateAgainst(std.testing.allocator, authority),
    );
    forged_plan = fixture.relation_plan;
    forged_plan.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.BindingSealMismatch,
        forged_plan.validateAgainst(std.testing.allocator, authority),
    );

    const saved_value = fixture.binding.entries[0].value;
    fixture.binding.entries[0].value = fixture.binding.entries[1].value;
    try std.testing.expectError(
        error.PlanBindingMismatch,
        relations.authenticate(std.testing.allocator, fixture.authority()),
    );
    fixture.binding.entries[0].value = saved_value;
}

test "Poseidon2 typed entries and batches exactly match narrow wide and io production rows" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const relation_challenges = challenges.Relations.dummy();
    const fixed = [_]production.Call{
        production.Call.narrow(0, 0),
        production.Call.narrow(11, 22),
        .{ .input = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, .wide = true },
        .{ .input = .{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }, .io = true },
    };
    for (fixed) |call| try expectCallMatches(&fixture, call, &relation_challenges);

    var prng = std.Random.DefaultPrng.init(0x4830_3036_72656c61);
    const random = prng.random();
    for (0..16) |index| {
        var call = production.Call{ .input = undefined };
        for (&call.input) |*value| value.* = random.int(u32) % m31.Modulus;
        switch (index % 3) {
            0 => {},
            1 => call.wide = true,
            2 => call.io = true,
            else => unreachable,
        }
        try expectCallMatches(&fixture, call, &relation_challenges);
    }
}

test "Poseidon2 typed interaction columns claims padding and replay match production" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const relation_challenges = challenges.Relations.dummy();
    const calls = [_]production.Call{
        production.Call.narrow(1, 2),
        .{ .input = .{ 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181 }, .wide = true },
        .{ .input = .{ 7, 11, 17, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73 }, .io = true },
    };
    var rows: [calls.len]relations.RelationRow = undefined;
    for (calls, &rows) |call, *row| {
        row.* = try fixture.relation_plan.rowFromMain(
            std.testing.allocator,
            fixture.authority(),
            production.fill(call),
        );
    }

    const expected_padding = production.paddingPairs();
    const actual_padding = relations.paddingPairs();
    for (actual_padding, expected_padding) |actual, expected| try expectPairEqual(actual, expected);

    var expected = try production.generateInteraction(
        std.testing.allocator,
        &calls,
        3,
        &relation_challenges,
    );
    defer expected.deinit(std.testing.allocator);
    var actual = try fixture.relation_plan.generateInteraction(
        std.testing.allocator,
        fixture.authority(),
        &rows,
        3,
        &relation_challenges,
    );
    defer actual.deinit(std.testing.allocator);
    try expectInteractionMatchesProduction(&actual, &expected);
    try fixture.relation_plan.validateInteraction(
        std.testing.allocator,
        fixture.authority(),
        &rows,
        3,
        &relation_challenges,
        &actual,
    );

    var replay = try fixture.relation_plan.generateInteraction(
        std.testing.allocator,
        fixture.authority(),
        &rows,
        3,
        &relation_challenges,
    );
    defer replay.deinit(std.testing.allocator);
    try expectTypedInteractionsEqual(&actual, &replay);

    try std.testing.expectError(
        error.InvalidTraceShape,
        fixture.relation_plan.generateInteraction(
            std.testing.allocator,
            fixture.authority(),
            &rows,
            1,
            &relation_challenges,
        ),
    );
}

test "Poseidon2 typed relation validation rejects tuple mode multiplicity order and claim forgeries" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const relation_challenges = challenges.Relations.dummy();
    const authority = fixture.authority();
    const honest_row = try fixture.relation_plan.rowFromMain(
        std.testing.allocator,
        authority,
        production.fill(production.Call.narrow(31, 41)),
    );
    const honest = try fixture.relation_plan.entries(
        std.testing.allocator,
        authority,
        honest_row,
    );
    try fixture.relation_plan.validateEntries(
        std.testing.allocator,
        authority,
        honest_row,
        honest,
    );

    var forged = honest;
    forged[0].values[0] = forged[0].values[0].add(QM31.one());
    try expectEntryError(&fixture, honest_row, forged, error.EntryTupleMismatch);
    forged = honest;
    forged[1].values[0] = forged[1].values[0].add(QM31.one());
    try expectEntryError(&fixture, honest_row, forged, error.EntryTupleMismatch);
    forged = honest;
    forged[1].numerator = forged[1].numerator.add(QM31.one());
    try expectEntryError(&fixture, honest_row, forged, error.EntryNumeratorMismatch);
    forged = honest;
    std.mem.swap(relations.Entry, &forged[0], &forged[1]);
    try expectEntryError(&fixture, honest_row, forged, error.EntryOrderMismatch);
    forged = honest;
    forged[0].domain = .poseidon2_io;
    try expectEntryError(&fixture, honest_row, forged, error.EntryDomainMismatch);
    forged = honest;
    forged[0].role = .consume;
    try expectEntryError(&fixture, honest_row, forged, error.EntryRoleMismatch);
    forged = honest;
    forged[1].semantic_width = 16;
    try expectEntryError(&fixture, honest_row, forged, error.EntryArityMismatch);

    var wide_row = honest_row;
    wide_row.wide = M31.one();
    try expectEntryError(&fixture, wide_row, honest, error.EntryNumeratorMismatch);
    var io_row = honest_row;
    io_row.io = M31.one();
    try expectEntryError(&fixture, io_row, honest, error.EntryNumeratorMismatch);

    const rows = [_]relations.RelationRow{honest_row};
    var interaction = try fixture.relation_plan.generateInteraction(
        std.testing.allocator,
        authority,
        &rows,
        2,
        &relation_challenges,
    );
    defer interaction.deinit(std.testing.allocator);
    interaction.claims.sums[0] = interaction.claims.sums[0].add(QM31.one());
    try std.testing.expectError(
        error.ClaimMismatch,
        fixture.relation_plan.validateInteraction(
            std.testing.allocator,
            authority,
            &rows,
            2,
            &relation_challenges,
            &interaction,
        ),
    );
    interaction.claims.sums[0] = interaction.claims.sums[0].sub(QM31.one());
    interaction.columns[0][0] = interaction.columns[0][0].add(M31.one());
    try std.testing.expectError(
        error.InteractionColumnMismatch,
        fixture.relation_plan.validateInteraction(
            std.testing.allocator,
            authority,
            &rows,
            2,
            &relation_challenges,
            &interaction,
        ),
    );
    const full_column = interaction.columns[0];
    interaction.columns[0] = full_column[0 .. full_column.len - 1];
    try std.testing.expectError(
        error.InteractionGeometryMismatch,
        fixture.relation_plan.validateInteraction(
            std.testing.allocator,
            authority,
            &rows,
            2,
            &relation_challenges,
            &interaction,
        ),
    );
    interaction.columns[0] = full_column;
}

test "Poseidon2 carried narrow output is exact and a mismatch cannot close against the committed row" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const relation_challenges = challenges.Relations.dummy();
    const plain = production.Call.narrow(31, 41);
    const main = production.fill(plain);
    const honest_row = try fixture.relation_plan.rowFromMain(
        std.testing.allocator,
        fixture.authority(),
        main,
    );
    const input = baseInput(plain.input);
    const carried = try fixture.relation_plan.carriedNarrowRow(
        std.testing.allocator,
        fixture.authority(),
        input,
        main[relations.OUTPUT_COLUMN_START],
    );
    const expected = production.rowPairsFromCall(
        production.Call.narrowWithOutput(31, 41, main[relations.OUTPUT_COLUMN_START].toU32()),
        &relation_challenges,
    );
    const actual = try fixture.relation_plan.rowPairs(
        std.testing.allocator,
        fixture.authority(),
        carried,
        &relation_challenges,
    );
    for (actual, expected) |actual_pair, expected_pair| try expectPairEqual(actual_pair, expected_pair);

    const merkle_counterpart = try narrowMerkleCounterpart(honest_row, &relation_challenges);
    const honest_claims = try fixture.relation_plan.rowClaims(
        std.testing.allocator,
        fixture.authority(),
        carried,
        &relation_challenges,
    );
    try honest_claims.verifyClosure(merkle_counterpart);

    const forged = try fixture.relation_plan.carriedNarrowRow(
        std.testing.allocator,
        fixture.authority(),
        input,
        main[relations.OUTPUT_COLUMN_START].add(M31.one()),
    );
    const forged_claims = try fixture.relation_plan.rowClaims(
        std.testing.allocator,
        fixture.authority(),
        forged,
        &relation_challenges,
    );
    try std.testing.expectError(
        error.RelationSumNonZero,
        forged_claims.verifyClosure(merkle_counterpart),
    );

    const forged_rows = [_]relations.RelationRow{forged};
    var forged_interaction = try fixture.relation_plan.generateInteraction(
        std.testing.allocator,
        fixture.authority(),
        &forged_rows,
        2,
        &relation_challenges,
    );
    defer forged_interaction.deinit(std.testing.allocator);
    const committed_rows = [_]relations.RelationRow{honest_row};
    try std.testing.expectError(
        error.ClaimMismatch,
        fixture.relation_plan.validateInteraction(
            std.testing.allocator,
            fixture.authority(),
            &committed_rows,
            2,
            &relation_challenges,
            &forged_interaction,
        ),
    );
}

test "Poseidon2 typed relation authentication and interaction clean up every allocation failure" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const relation_challenges = challenges.Relations.dummy();
    const rows = [_]relations.RelationRow{
        try fixture.relation_plan.rowFromMain(
            std.testing.allocator,
            fixture.authority(),
            production.fill(production.Call.narrow(1, 2)),
        ),
        try fixture.relation_plan.rowFromMain(
            std.testing.allocator,
            fixture.authority(),
            production.fill(.{ .input = .{1} ** production.WIDTH, .wide = true }),
        ),
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &fixture, &rows, &relation_challenges },
    );
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    rows: []const relations.RelationRow,
    relation_challenges: *const challenges.Relations,
) !void {
    const plan = try relations.authenticate(allocator, fixture.authority());
    var interaction = try plan.generateInteraction(
        allocator,
        fixture.authority(),
        rows,
        2,
        relation_challenges,
    );
    defer interaction.deinit(allocator);
    try plan.validateInteraction(
        allocator,
        fixture.authority(),
        rows,
        2,
        relation_challenges,
        &interaction,
    );
}

fn expectCallMatches(
    fixture: *const Fixture,
    call: production.Call,
    relation_challenges: *const challenges.Relations,
) !void {
    const main = production.fill(call);
    const secure_main = secure(main);
    const row = try fixture.relation_plan.rowFromMain(
        std.testing.allocator,
        fixture.authority(),
        main,
    );
    const actual_entries = try fixture.relation_plan.entries(
        std.testing.allocator,
        fixture.authority(),
        row,
    );
    const expected_entries = production.entries(secure_main);
    try std.testing.expectEqual(@as(usize, relations.N_EVENTS), expected_entries.len);
    try std.testing.expectEqual(@as(usize, relations.N_BATCHES), expected_entries.batchCount());
    for (actual_entries, expected_entries.entries[0..expected_entries.len]) |actual, expected| {
        try expectEntryMatchesProduction(actual, expected);
    }
    const actual_pairs = try fixture.relation_plan.rowPairs(
        std.testing.allocator,
        fixture.authority(),
        row,
        relation_challenges,
    );
    const expected_pairs = production.rowPairs(secure_main, relation_challenges);
    for (actual_pairs, expected_pairs) |actual, expected| try expectPairEqual(actual, expected);
}

fn expectEntryMatchesProduction(actual: relations.Entry, expected: lookup_entry.Entry) !void {
    try std.testing.expectEqual(@intFromEnum(expected.domain), @intFromEnum(actual.domain));
    try std.testing.expectEqual(@intFromEnum(expected.role), @intFromEnum(actual.role));
    try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
    try std.testing.expectEqual(expected.arity, actual.arity);
    try std.testing.expect(actual.numerator.eql(expected.numerator));
    for (actual.values[0..actual.arity], expected.values[0..expected.arity]) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

fn expectPairEqual(actual: logup.RowPair, expected: logup.RowPair) !void {
    try std.testing.expect(actual.n1.eql(expected.n1));
    try std.testing.expect(actual.d1.eql(expected.d1));
    try std.testing.expect(actual.n2.eql(expected.n2));
    try std.testing.expect(actual.d2.eql(expected.d2));
}

fn expectInteractionMatchesProduction(
    actual: *const relations.Interaction,
    expected: *const production.Interaction,
) !void {
    for (actual.claims.sums, expected.claims.sums) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
    for (actual.columns, expected.columns) |actual_column, expected_column| {
        try std.testing.expectEqual(actual_column.len, expected_column.len);
        for (actual_column, expected_column) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
    }
}

fn expectTypedInteractionsEqual(
    actual: *const relations.Interaction,
    expected: *const relations.Interaction,
) !void {
    try std.testing.expect(actual.claims.eql(expected.claims));
    for (actual.columns, expected.columns) |actual_column, expected_column| {
        for (actual_column, expected_column) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
    }
}

fn expectEntryError(
    fixture: *const Fixture,
    row: relations.RelationRow,
    entries: [relations.N_EVENTS]relations.Entry,
    expected: anyerror,
) !void {
    try std.testing.expectError(
        expected,
        fixture.relation_plan.validateEntries(
            std.testing.allocator,
            fixture.authority(),
            row,
            entries,
        ),
    );
}

fn narrowMerkleCounterpart(
    row: relations.RelationRow,
    relation_challenges: *const challenges.Relations,
) !QM31 {
    var input = [_]QM31{QM31.zero()} ** relations.WIDTH;
    var output = [_]QM31{QM31.zero()} ** relations.WIDTH;
    for (&input, row.input) |*value, source_value| value.* = QM31.fromBase(source_value);
    output[0] = QM31.fromBase(row.output[0]);
    return (try relation_challenges.poseidon2.combineSecure(input).inv())
        .sub(try relation_challenges.poseidon2.combineSecure(output).inv());
}

fn baseInput(input: [production.WIDTH]u32) [relations.WIDTH]M31 {
    var result: [relations.WIDTH]M31 = undefined;
    for (&result, input) |*value, source_value| value.* = M31.fromU64(source_value);
    return result;
}

fn secure(row: [production.N_MAIN_COLUMNS]M31) [production.N_MAIN_COLUMNS]QM31 {
    var result: [production.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, row) |*value, source_value| value.* = QM31.fromBase(source_value);
    return result;
}

const Fixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,
    materialization_plan: materializer.Plan,
    binding: compat.OwnedBinding,
    relation_plan: relations.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource("air/components/poseidon2_m31.relations.zig");
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        const roots = poseidon.values(definition.outputs);
        var materialization_plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        errdefer materialization_plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        var binding = try compat.bindPlan(
            allocator,
            &arena,
            definition,
            spans,
            schedule,
            &materialization_plan,
        );
        errdefer binding.deinit(allocator);
        var result = Fixture{
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
            .materialization_plan = materialization_plan,
            .binding = binding,
            .relation_plan = undefined,
        };
        result.relation_plan = try relations.authenticate(allocator, result.authority());
        return result;
    }

    fn deinit(self: *Fixture) void {
        const allocator = self.arena.allocator;
        self.binding.deinit(allocator);
        self.materialization_plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    fn authority(self: *const Fixture) relations.Authority {
        return .{
            .arena = &self.arena,
            .definition = self.definition,
            .spans = self.spans,
            .materialization_plan = &self.materialization_plan,
            .binding = &self.binding,
        };
    }
};

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var next_line: u32 = 2;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
