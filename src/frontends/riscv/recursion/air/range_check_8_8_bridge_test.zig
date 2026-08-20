//! Exactness, source-authentication, and hot-writer gates for universal row 35.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const protocol_degree = @import("../../air/lang/protocol_degree.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const lookup_counter = @import("../../air/lookups/tables/counter.zig");
const lookup_interaction = @import("../../air/lookups/tables/interaction.zig");
const lookup_relations = @import("../../air/relation_challenges.zig");
const lookup_schema = @import("../../air/lookups/tables/schema.zig");
const bridge = @import("range_check_8_8_bridge.zig");
const universal = @import("universal_challenges.zig");

test "R-012 range-check 8-8 bridge pins exact source geometry and identities" {
    const authority = bridge.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        bridge.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqualStrings(
        "59172a201bd01f2f4b699bc2f7d4442d8ee81597",
        &authority.revision,
    );
    try std.testing.expectEqual(@as(u32, 16), authority.log_size);
    try std.testing.expectEqual(@as(u8, 2), authority.tuple_arity);
    try std.testing.expectEqual(@as(u8, 1), authority.main_columns);
    try std.testing.expectEqual(@as(u8, 3), authority.preprocessed_columns);
    try std.testing.expectEqual(@as(u8, 4), authority.interaction_columns);
    try std.testing.expectEqual(@as(u8, 1), authority.framework_constraints);
    try std.testing.expectEqual(relation.Role.consume, authority.relation_role);
    try std.testing.expectEqual(relation.Role.request, bridge.BASE_ABI_RELATION_ROLE);

    const unchecked_identity = try bridge.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        bridge.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(unchecked_identity.bytes, .lower),
    );

    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 3), definition.main.physical().len + definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 0), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 1), definition.arena.effectsView().len);
    const identity = try bridge.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        bridge.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    const binding = try bridge.Binding.canonical(&definition);
    const actual_binding_digest = binding.identityDigest();
    try std.testing.expectEqualStrings(
        bridge.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(actual_binding_digest, .lower),
    );
    const plan = try bridge.authenticateRelation(&definition);
    try plan.validateAgainst(
        &definition.arena,
        bridge.SEMANTIC_DIGEST,
        definition.events,
    );
    try std.testing.expectEqual(@as(usize, 1), plan.events.len);
    try std.testing.expectEqual(relation.Domain.range_check_8_8, plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.request, plan.events[0].role);
    try std.testing.expectEqual(@as(u8, 2), plan.events[0].arity);
}

test "R-012 range-check 8-8 bridge exposes zero duplicate AIR and exact degree cost" {
    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = bridge.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = bridge.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 3), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 1), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 3), profile.constraint_effect_reachable_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);

    const terms = try protocol_degree.interactionTerms(.{
        .numerator = 1,
        .denominator = 1,
    }, null);
    try std.testing.expectEqual(@as(u32, 2), terms.final);
    try std.testing.expectEqual(@as(u8, 0), protocol_degree.quotientExpansionBits(terms.final));
    // Stark-V's macro advertises log_size + 1 uniformly; keep that exact
    // source bound even though this singleton recurrence models as quadratic.
    try std.testing.expectEqual(@as(u32, 17), bridge.MAXIMUM_CONSTRAINT_LOG_DEGREE_BOUND);
}

test "R-012 range-check 8-8 writers preserve every upstream row without hot allocation" {
    var source_counter = try fixtureCounter(std.testing.allocator);
    defer source_counter.deinit(std.testing.allocator);
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try bridge.PreparedBatch.init(measured.allocator(), &source_counter);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    try batch.validateAgainstSource(&source_counter);

    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try bridge.Binding.canonical(&definition);
    const executor = try bridge.Executor.init(&definition, &binding);
    const storage = try std.testing.allocator.alloc(M31, bridge.LOGICAL_INPUT_COUNT * bridge.TABLE_SIZE);
    defer std.testing.allocator.free(storage);
    @memset(storage, M31.fromCanonical(0x5151));
    var main: [bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    var preprocessed: [bridge.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(bridge.PHYSICAL_MAIN_COLUMN_COUNT, bridge.TABLE_SIZE, storage[0..bridge.TABLE_SIZE], &main);
    splitColumns(bridge.PREPROCESSED_COLUMN_COUNT, bridge.TABLE_SIZE, storage[bridge.TABLE_SIZE..], &preprocessed);
    const before = measured.alloc_index;
    try executor.generateTraceInto(&batch, &main, &preprocessed);
    try std.testing.expectEqual(before, measured.alloc_index);

    var nonzero: usize = 0;
    for (0..bridge.TABLE_SIZE) |logical_row| {
        const dst = bridge.committedRow(logical_row);
        const tuple = try lookup_schema.tupleAt(bridge.TABLE_KIND, logical_row);
        try std.testing.expect(main[0][dst].eql(source_counter.values[logical_row]));
        try std.testing.expect(preprocessed[0][dst].eql(tuple.values[0]));
        try std.testing.expect(preprocessed[1][dst].eql(tuple.values[1]));
        nonzero += @intFromBool(!main[0][dst].isZero());
    }
    // Unused table rows are present with zero multiplicity; the fixed domain
    // is never shortened around a sparse workload.
    try std.testing.expectEqual(@as(usize, 3), nonzero);

    @memset(storage, M31.fromCanonical(0x5252));
    const before_split = measured.alloc_index;
    try executor.generateMainInto(&batch, &main);
    try executor.generatePreprocessedInto(&batch, &preprocessed);
    try std.testing.expectEqual(before_split, measured.alloc_index);
    for ([_]usize{ 0, 1, 255, 256, 513, 65_535 }) |logical_row| {
        const dst = bridge.committedRow(logical_row);
        const expected = bridge.relationRow(source_counter.values[logical_row], logical_row);
        try std.testing.expect(main[0][dst].eql(expected[0]));
        try std.testing.expect(preprocessed[0][dst].eql(expected[1]));
        try std.testing.expect(preprocessed[1][dst].eql(expected[2]));
    }
}

test "R-012 range-check 8-8 typed relation equals native provider and cancels requests" {
    var source_counter = try fixtureCounter(std.testing.allocator);
    defer source_counter.deinit(std.testing.allocator);
    var batch = try bridge.PreparedBatch.init(std.testing.allocator, &source_counter);
    defer batch.deinit();
    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try bridge.Binding.canonical(&definition);
    const executor = try bridge.Executor.init(&definition, &binding);
    const plan = try bridge.authenticateRelation(&definition);

    for ([_]usize{ 0, 1, 256, 513, 0x3412, 65_535 }) |logical_row| {
        const row = batch.preparedRelationRow(logical_row);
        const entries = try plan.entries(
            &definition.arena,
            bridge.SEMANTIC_DIGEST,
            definition.events,
            row,
        );
        const tuple = try lookup_schema.tupleAt(bridge.TABLE_KIND, logical_row);
        const native = lookup_interaction.tableEntry(
            bridge.TABLE_KIND,
            tuple,
            source_counter.values[logical_row],
        );
        try std.testing.expectEqual(relation.Domain.range_check_8_8, entries[0].domain);
        try std.testing.expectEqual(relation.Role.request, entries[0].role);
        try std.testing.expect(entries[0].numerator.eql(native.numerator));
        try std.testing.expectEqual(@as(u8, 2), entries[0].arity);
        for (0..2) |index| try std.testing.expect(
            entries[0].values[index].eql(native.values[index]),
        );
    }

    const rows = try std.testing.allocator.alloc(bridge.RelationRow, bridge.TABLE_SIZE);
    defer std.testing.allocator.free(rows);
    try executor.generateRelationRowsInto(&batch, rows);
    const recursive_relations = universal.UniversalRelations.dummy();
    var typed = try plan.generateInteraction(
        std.testing.allocator,
        &definition.arena,
        bridge.SEMANTIC_DIGEST,
        definition.events,
        rows,
        bridge.LOG_SIZE,
        &recursive_relations,
    );
    defer typed.deinit(std.testing.allocator);
    const native_relations = lookup_relations.Relations.dummy();
    var native = try batch.generateNativeInteraction(
        std.testing.allocator,
        &native_relations,
    );
    defer native.deinit(std.testing.allocator);
    try std.testing.expect(typed.claims.total().eql(native.claim));

    var request_sum = QM31.zero();
    for (source_counter.values, 0..) |multiplicity, logical_row| {
        if (multiplicity.isZero()) continue;
        const tuple = try lookup_schema.tupleAt(bridge.TABLE_KIND, logical_row);
        const denominator = native_relations.range_check_8_8.combineBase(tuple.values[0..2].*);
        request_sum = request_sum.add(
            QM31.fromBase(multiplicity).mul(try denominator.inv()),
        );
    }
    try std.testing.expect(request_sum.add(native.claim).isZero());
}

test "R-012 range-check 8-8 seals aliases and failures before every first store" {
    var source_counter = try fixtureCounter(std.testing.allocator);
    defer source_counter.deinit(std.testing.allocator);
    var batch = try bridge.PreparedBatch.init(std.testing.allocator, &source_counter);
    defer batch.deinit();
    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try bridge.Binding.canonical(&definition);
    const executor = try bridge.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x6161);
    const storage = try std.testing.allocator.alloc(M31, bridge.LOGICAL_INPUT_COUNT * bridge.TABLE_SIZE);
    defer std.testing.allocator.free(storage);
    var main: [bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    var preprocessed: [bridge.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(bridge.PHYSICAL_MAIN_COLUMN_COUNT, bridge.TABLE_SIZE, storage[0..bridge.TABLE_SIZE], &main);
    splitColumns(bridge.PREPROCESSED_COLUMN_COUNT, bridge.TABLE_SIZE, storage[bridge.TABLE_SIZE..], &preprocessed);

    @memset(storage, sentinel);
    var short = main;
    short[0] = short[0][0 .. bridge.TABLE_SIZE - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateTraceInto(&batch, &short, &preprocessed),
    );
    try expectAll(storage, sentinel);

    var duplicate = preprocessed;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateTraceInto(&batch, &main, &duplicate),
    );
    try expectAll(storage, sentinel);

    var cross_alias = main;
    cross_alias[0] = preprocessed[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateTraceInto(&batch, &cross_alias, &preprocessed),
    );
    try expectAll(storage, sentinel);

    var source_alias = [bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31{batch.counter.values};
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&batch, &source_alias),
    );
    try batch.validateAgainstSource(&source_counter);

    batch.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        executor.generateTraceInto(&batch, &main, &preprocessed),
    );
    try expectAll(storage, sentinel);
    batch.authority_digest[0] ^= 1;

    const original = batch.counter.values[513];
    batch.counter.values[513] = M31.fromU32Unchecked(m31.Modulus);
    try std.testing.expectError(
        error.InvalidFieldElement,
        executor.generateTraceInto(&batch, &main, &preprocessed),
    );
    try expectAll(storage, sentinel);
    batch.counter.values[513] = original;
    try batch.validate();

    var mutated_binding = binding;
    mutated_binding.preprocessed[0].column = 1;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        bridge.Executor.init(&definition, &mutated_binding),
    );
    var mutated_authority = bridge.SourceAuthority.pinned();
    mutated_authority.table_sha256[0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, mutated_authority.validate());

    const plan = try bridge.authenticateRelation(&definition);
    const row = batch.preparedRelationRow(513);
    var entries = try plan.entries(
        &definition.arena,
        bridge.SEMANTIC_DIGEST,
        definition.events,
        row,
    );
    entries[0].role = .emit;
    try std.testing.expectError(
        error.EntryRoleMismatch,
        plan.validateEntries(
            &definition.arena,
            bridge.SEMANTIC_DIGEST,
            definition.events,
            row,
            entries,
        ),
    );
    var mutated_plan = plan;
    mutated_plan.events[0].arity = 1;
    try std.testing.expectError(
        error.EventPlanMismatch,
        mutated_plan.validateAgainst(
            &definition.arena,
            bridge.SEMANTIC_DIGEST,
            definition.events,
        ),
    );
}

test "R-012 range-check 8-8 relation-row materialization is padded and atomic" {
    var source_counter = try fixtureCounter(std.testing.allocator);
    defer source_counter.deinit(std.testing.allocator);
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try bridge.PreparedBatch.init(measured.allocator(), &source_counter);
    defer batch.deinit();
    var definition = try bridge.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try bridge.Binding.canonical(&definition);
    const executor = try bridge.Executor.init(&definition, &binding);
    const rows = try std.testing.allocator.alloc(bridge.RelationRow, bridge.TABLE_SIZE);
    defer std.testing.allocator.free(rows);
    const before = measured.alloc_index;
    try executor.generateRelationRowsInto(&batch, rows);
    try std.testing.expectEqual(before, measured.alloc_index);
    for ([_]usize{ 0, 1, 255, 256, 513, 0x3412, 65_535 }) |row|
        try std.testing.expectEqualDeep(bridge.relationRow(source_counter.values[row], row), rows[row]);

    const sentinel = bridge.RelationRow{ M31.fromCanonical(7), M31.fromCanonical(8), M31.fromCanonical(9) };
    @memset(rows, sentinel);
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateRelationRowsInto(&batch, rows[0 .. rows.len - 1]),
    );
    for (rows) |row| try std.testing.expectEqualDeep(sentinel, row);
}

test "R-012 range-check 8-8 construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        definitionAllocationFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        batchAllocationFailureCase,
        .{},
    );
}

fn definitionAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try bridge.build(allocator);
    defer definition.deinit();
    const binding = try bridge.Binding.canonical(&definition);
    _ = try bridge.Executor.init(&definition, &binding);
    _ = try bridge.authenticateRelation(&definition);
}

fn batchAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var counter = try fixtureCounter(std.testing.allocator);
    defer counter.deinit(std.testing.allocator);
    var batch = try bridge.PreparedBatch.init(allocator, &counter);
    defer batch.deinit();
    try batch.validateAgainstSource(&counter);
}

fn fixtureCounter(allocator: std.mem.Allocator) !lookup_counter.Counter {
    var counter = try lookup_counter.Counter.init(allocator, bridge.TABLE_KIND);
    errdefer counter.deinit(allocator);
    try counter.registerRaw(QM31.one().neg(), &.{ q(1), q(2) });
    try counter.registerRaw(QM31.one().neg(), &.{ q(0x12), q(0x34) });
    try counter.registerRaw(QM31.one().neg(), &.{ q(255), q(255) });
    return counter;
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    std.debug.assert(storage.len == count * size);
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

fn expectAll(values: []const M31, expected: M31) !void {
    for (values) |value| try std.testing.expect(value.eql(expected));
}
