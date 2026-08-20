//! Exactness, profile, mutation, and performance gates for row 16.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const types = @import("../../air/lang/types.zig");
const relation = @import("../../air/lang/relation.zig");
const air = @import("vm_public_logup_input.zig");
const witness = @import("vm_public_logup_input_witness.zig");
const relation_plan = @import("vm_public_logup_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");

const CLAIM_KINDS = [_]witness.ClaimKind{ .constant, .u16, .boolean, .field };
const CLAIMED_SUM_COUNT: u32 = 2;
const ROW_COUNT: usize = 47;

test "R-012 exact VM public-LogUp input geometry seal and relation order" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 2), air.PHYSICAL_MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 11), air.PREPROCESSED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 5), air.PROOF_KIND_PARAMETER_COUNT);
    try std.testing.expectEqual(@as(usize, 3), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 5), definition.arena.effectsView().len);
    try std.testing.expectEqual(@as(u16, 7), plan.compiled_node_count);
    const expected_domains = [_]relation.Domain{
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_byte,
        .recursion_relation_challenge_word,
        .recursion_verifier_input_word,
        .recursion_wire,
    };
    const expected_roles = [_]relation.Role{
        .consume,
        .consume,
        .consume,
        .consume,
        .emit,
    };
    for (plan.events, expected_domains, expected_roles, 0..) |
        event,
        domain,
        role,
        index,
    | {
        try std.testing.expectEqual(@as(u8, @intCast(index)), event.ordinal);
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
}

test "R-012 VM public-LogUp canonical O(n) profile rejects source deformation" {
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    try reference.validate();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expect(std.meta.eql(
        bindings[0].source,
        witness.Source.segment_selector,
    ));
    try std.testing.expect(std.meta.eql(
        bindings[3].source,
        witness.Source{ .claim_byte = .{ .word_index = 1, .byte_index = 0 } },
    ));
    try std.testing.expect(std.meta.eql(
        bindings[7].source,
        witness.Source{ .relation_challenge_word = .{
            .challenge = 0,
            .word_index = 0,
        } },
    ));
    try std.testing.expect(std.meta.eql(
        bindings[39].source,
        witness.Source{ .claimed_sum_word = .{
            .item_index = 0,
            .limb_index = 0,
        } },
    ));

    const saved = bindings[2].source;
    bindings[2].source = bindings[1].source;
    try std.testing.expectError(error.SourceOrderMismatch, reference.validate());
    bindings[2].source = saved;
    bindings[2].node_id = bindings[1].node_id;
    try std.testing.expectError(error.NodeOrderNotCanonical, reference.validate());
    bindings[2].node_id += 1;
    bindings[0].use_count += 1;
    try std.testing.expectError(error.ReferenceDigestMismatch, reference.validate());
    bindings[0].use_count -= 1;
    preprocessing.rows[0].source_index_0 = 1;
    try std.testing.expectError(
        error.InputLayoutMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 VM public-LogUp witnesses and direct constraints cover every mode" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const segment_values = fixtureValues();
    const inactive_values = [_]M31{M31.zero()} ** ROW_COUNT;

    for ([_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf }) |kind| {
        const values = if (kind == .segment_leaf) segment_values else inactive_values;
        var main = try witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            reference,
            &values,
            kind,
        );
        defer main.deinit();
        try main.validateAgainst(&preprocessing);
        for (preprocessing.rows, values) |metadata, value| {
            const input_row = logical(.{ .value = value }, metadata, kind);
            const evaluated = try support.evaluateArena(
                std.testing.allocator,
                &definition.arena,
                &input_row,
            );
            defer std.testing.allocator.free(evaluated);
            for (definition.constraints) |constraint_id| {
                const constraint = definition.arena.constraint(constraint_id).?;
                try std.testing.expect(
                    evaluated[types.idIndex(constraint.root)].isZero(),
                );
            }
        }
    }

    var forged = inactive_values;
    forged[1] = M31.one();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            reference,
            &forged,
            .binary_node,
        ),
    );
    forged[1] = M31.zero();
    forged[0] = M31.one();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            reference,
            &forged,
            .empty_leaf,
        ),
    );
}

test "R-012 VM public-LogUp relation weights match every source class" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const values = fixtureValues();
    const cases = [_]struct { row: usize, event: usize }{
        .{ .row = 1, .event = 0 },
        .{ .row = 3, .event = 1 },
        .{ .row = 7, .event = 2 },
        .{ .row = 39, .event = 3 },
    };
    for (cases) |case| {
        const entries = try plan.entries(
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            logical(
                .{ .value = values[case.row] },
                preprocessing.rows[case.row],
                .segment_leaf,
            ),
        );
        for (entries[0..4], 0..) |entry, index| try std.testing.expect(
            entry.numerator.eql(
                if (index == case.event) QM31.one().neg() else QM31.zero(),
            ),
        );
        try std.testing.expect(entries[4].numerator.eql(QM31.fromBase(
            M31.fromCanonical(preprocessing.rows[case.row].use_count),
        )));
    }
    const selector_entries = try plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        definition.events,
        logical(.{ .value = M31.one() }, preprocessing.rows[0], .segment_leaf),
    );
    for (selector_entries[0..4]) |entry|
        try std.testing.expect(entry.numerator.isZero());
    try std.testing.expect(selector_entries[4].numerator.eql(QM31.fromBase(
        M31.fromCanonical(preprocessing.rows[0].use_count),
    )));
    const inactive_entries = try plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        definition.events,
        logical(.{ .value = M31.zero() }, preprocessing.rows[1], .empty_leaf),
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 VM public-LogUp writers are allocation-free padded and atomic" {
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        reference,
        &fixtureValues(),
        .segment_leaf,
    );
    defer main.deinit();
    try assertWriter(
        air.PHYSICAL_MAIN_COLUMN_COUNT,
        &main,
        &preprocessing,
        preprocessing.log_size,
    );
    try assertWriter(
        air.PREPROCESSED_COLUMN_COUNT,
        &preprocessing,
        reference,
        preprocessing.log_size,
    );
}

test "R-012 VM public-LogUp interaction is cache bounded and failure atomic" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const values = fixtureValues();
    var rows: [ROW_COUNT]relation_plan.Row = undefined;
    for (&rows, preprocessing.rows, values) |*row, metadata, value|
        row.* = logical(.{ .value = value }, metadata, .segment_leaf);
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            preprocessing.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, preprocessing.log_size, &relations },
    );
}

test "R-012 VM public-LogUp construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
    var bindings = fixtureBindings();
    const reference = try fixtureReference(&bindings);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{reference},
    );
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        mainFailureCase,
        .{ &preprocessing, reference },
    );
}

fn logical(
    main: witness.MainRow,
    preprocessing: witness.PreprocessedRow,
    kind: witness.ProofKind,
) [air.LOGICAL_INPUT_COUNT]M31 {
    return witness.logicalInputs(
        main,
        preprocessing,
        kind,
        M31.fromCanonical(17),
        M31.fromCanonical(0),
        M31.fromCanonical(23),
        M31.fromCanonical(7),
    );
}

fn fixtureReference(bindings: []const witness.Binding) !witness.Reference {
    return witness.Reference.seal(
        41,
        &CLAIM_KINDS,
        CLAIMED_SUM_COUNT,
        bindings,
    );
}

fn fixtureBindings() [ROW_COUNT]witness.Binding {
    var result: [ROW_COUNT]witness.Binding = undefined;
    var cursor: usize = 0;
    appendBinding(&result, &cursor, .segment_selector);
    for (CLAIM_KINDS, 0..) |kind, word_index| {
        appendBinding(&result, &cursor, .{ .claim_word = @intCast(word_index) });
        if (kind == .u16) {
            appendBinding(&result, &cursor, .{ .claim_byte = .{
                .word_index = @intCast(word_index),
                .byte_index = 0,
            } });
            appendBinding(&result, &cursor, .{ .claim_byte = .{
                .word_index = @intCast(word_index),
                .byte_index = 1,
            } });
        }
    }
    for (witness.CHALLENGES) |challenge| for (0..witness.CHALLENGE_WORD_COUNT) |word_index|
        appendBinding(&result, &cursor, .{ .relation_challenge_word = .{
            .challenge = challenge,
            .word_index = @intCast(word_index),
        } });
    for (0..CLAIMED_SUM_COUNT) |item_index| for (0..witness.QM31_LIMB_COUNT) |limb_index|
        appendBinding(&result, &cursor, .{ .claimed_sum_word = .{
            .item_index = @intCast(item_index),
            .limb_index = @intCast(limb_index),
        } });
    std.debug.assert(cursor == result.len);
    return result;
}

fn appendBinding(
    result: *[ROW_COUNT]witness.Binding,
    cursor: *usize,
    source: witness.Source,
) void {
    result[cursor.*] = .{
        .node_id = @intCast(cursor.* + 1),
        .use_count = @intCast(cursor.* % 3 + 1),
        .source = source,
    };
    cursor.* += 1;
}

fn fixtureValues() [ROW_COUNT]M31 {
    var result: [ROW_COUNT]M31 = undefined;
    for (&result, 0..) |*value, index|
        value.* = if (index == 0) M31.one() else M31.fromCanonical(@intCast(index + 5));
    return result;
}

fn assertWriter(
    comptime column_count: usize,
    writer: anytype,
    authority: anytype,
    log_size: u32,
) !void {
    const size = @as(usize, 1) << @intCast(log_size);
    const storage = try std.testing.allocator.alloc(M31, column_count * size);
    defer std.testing.allocator.free(storage);
    @memset(storage, M31.fromCanonical(99));
    var columns: [column_count][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try writer.generateInto(&columns, authority);
    for (columns) |column| for (column[writer.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    const snapshot = try std.testing.allocator.dupe(M31, storage);
    defer std.testing.allocator.free(snapshot);
    columns[1] = columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        writer.generateInto(&columns, authority),
    );
    try std.testing.expectEqualSlices(M31, snapshot, storage);
}

fn buildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try air.build(allocator);
    defer definition.deinit();
}

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    reference: witness.Reference,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
}

fn mainFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    reference: witness.Reference,
) !void {
    var main = try witness.MainWitness.init(
        allocator,
        preprocessing,
        reference,
        &fixtureValues(),
        .segment_leaf,
    );
    defer main.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const air.Definition,
    plan: *const relation_plan.Plan,
    rows: []const relation_plan.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        air.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}
