//! Exactness, adversarial, allocation, and hot-path gates for row 15.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const types = @import("../../air/lang/types.zig");
const relation = @import("../../air/lang/relation.zig");
const air = @import("vm_public_claim_semantics_input.zig");
const witness = @import("vm_public_claim_semantics_input_witness.zig");
const relation_plan = @import("vm_public_claim_semantics_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");

test "R-012 exact VM claim-semantics input geometry seal and relation order" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 2), air.PHYSICAL_MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 11), air.PREPROCESSED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 3), air.PROOF_KIND_PARAMETER_COUNT);
    try std.testing.expectEqual(@as(usize, 3), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 4), definition.arena.effectsView().len);
    try std.testing.expectEqual(@as(u16, 6), plan.compiled_node_count);
    const expected_domains = [_]relation.Domain{
        .recursion_vm_public_claim_word,
        .recursion_statement_word,
        .recursion_vm_public_io_digest,
        .recursion_wire,
    };
    const expected_roles = [_]relation.Role{ .consume, .consume, .consume, .emit };
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

test "R-012 VM claim-semantics reference and witnesses fail closed" {
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
    try reference.validate();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);

    var segment = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        reference,
        &segmentValues(),
        .segment_leaf,
    );
    defer segment.deinit();
    try segment.validateAgainst(&preprocessing);

    var inactive = [_]M31{M31.zero()} ** 5;
    var binary = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        reference,
        &inactive,
        .binary_node,
    );
    defer binary.deinit();
    try binary.validateAgainst(&preprocessing);

    inactive[0] = M31.one();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            reference,
            &inactive,
            .empty_leaf,
        ),
    );
    var bad_selector = segmentValues();
    bad_selector[2] = M31.zero();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            reference,
            &bad_selector,
            .segment_leaf,
        ),
    );

    bindings[0].use_count += 1;
    try std.testing.expectError(error.ReferenceDigestMismatch, reference.validate());
    bindings[0].use_count -= 1;
    preprocessing.rows[0].node_id += 1;
    try std.testing.expectError(
        error.InputLayoutMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 VM claim-semantics direct constraints hold in every proof mode" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const claim_scope = M31.fromCanonical(17);
    const statement_scope = M31.fromCanonical(19);

    for ([_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf }) |kind| {
        const values = if (kind == .segment_leaf)
            segmentValues()
        else
            [_]M31{M31.zero()} ** 5;
        for (preprocessing.rows, values) |metadata, value| {
            const logical = witness.logicalInputs(
                .{ .value = value },
                metadata,
                kind,
                claim_scope,
                statement_scope,
            );
            const evaluated = try support.evaluateArena(
                std.testing.allocator,
                &definition.arena,
                &logical,
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

    var forged = witness.logicalInputs(
        .{ .value = M31.one() },
        preprocessing.rows[0],
        .binary_node,
        claim_scope,
        statement_scope,
    );
    var evaluated = try support.evaluateArena(
        std.testing.allocator,
        &definition.arena,
        &forged,
    );
    defer std.testing.allocator.free(evaluated);
    try std.testing.expect(!evaluated[types.idIndex(definition.roots[1])].isZero());
    forged[0] = M31.zero();
    const enabler_values = try support.evaluateArena(
        std.testing.allocator,
        &definition.arena,
        &forged,
    );
    defer std.testing.allocator.free(enabler_values);
    try std.testing.expect(!enabler_values[types.idIndex(definition.roots[0])].isZero());
}

test "R-012 VM claim-semantics relation weights are source exact" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const values = segmentValues();
    for (preprocessing.rows, values, 0..) |metadata, value, index| {
        const logical = witness.logicalInputs(
            .{ .value = value },
            metadata,
            .segment_leaf,
            M31.fromCanonical(17),
            M31.fromCanonical(19),
        );
        const entries = try plan.entries(
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            logical,
        );
        try std.testing.expect(entries[0].numerator.eql(
            if (index == 0) QM31.one().neg() else QM31.zero(),
        ));
        try std.testing.expect(entries[1].numerator.eql(
            if (index == 1) QM31.one().neg() else QM31.zero(),
        ));
        try std.testing.expect(entries[2].numerator.eql(
            if (index == 4) QM31.one().neg() else QM31.zero(),
        ));
        try std.testing.expect(entries[3].numerator.eql(
            QM31.fromBase(M31.fromCanonical(metadata.use_count)),
        ));
    }
    const inactive = witness.logicalInputs(
        .{ .value = M31.zero() },
        preprocessing.rows[0],
        .empty_leaf,
        M31.fromCanonical(17),
        M31.fromCanonical(19),
    );
    const entries = try plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        definition.events,
        inactive,
    );
    for (entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 VM claim-semantics writers zero pad reject alias and allocate only cold" {
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        reference,
        &segmentValues(),
        .segment_leaf,
    );
    defer main.deinit();
    try assertWriter(
        air.PHYSICAL_MAIN_COLUMN_COUNT,
        &main,
        &preprocessing,
        true,
    );
    try assertWriter(
        air.PREPROCESSED_COLUMN_COUNT,
        &preprocessing,
        reference,
        false,
    );
}

test "R-012 VM claim-semantics interaction is cache bounded and failure atomic" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        reference,
    );
    defer preprocessing.deinit();
    const values = segmentValues();
    var rows: [5]relation_plan.Row = undefined;
    for (&rows, preprocessing.rows, values) |*row, metadata, value| row.* =
        witness.logicalInputs(
            .{ .value = value },
            metadata,
            .segment_leaf,
            M31.fromCanonical(17),
            M31.fromCanonical(19),
        );
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

test "R-012 VM claim-semantics construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
    var bindings = fixtureBindings();
    const reference = try witness.Reference.seal(41, &bindings);
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

fn assertWriter(
    comptime column_count: usize,
    writer: anytype,
    authority: anytype,
    comptime main: bool,
) !void {
    const size = @as(usize, 1) << @intCast(if (main)
        authority.log_size
    else
        writer.log_size);
    const storage = try std.testing.allocator.alloc(M31, column_count * size);
    defer std.testing.allocator.free(storage);
    @memset(storage, M31.fromCanonical(99));
    var columns: [column_count][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try writer.generateInto(&columns, authority);
    const row_count = writer.rows.len;
    for (columns) |column| for (column[row_count..]) |padding|
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

fn fixtureBindings() [5]witness.Binding {
    return .{
        .{ .source = .claim, .node_id = 1, .use_count = 2, .word_index = 0 },
        .{ .source = .statement, .node_id = 2, .use_count = 1, .word_index = 3 },
        .{ .source = .selector, .node_id = 3, .use_count = 4 },
        .{ .source = .private, .node_id = 4, .use_count = 1 },
        .{ .source = .io_digest, .node_id = 5, .use_count = 2, .word_index = 7, .io_kind = 1 },
    };
}

fn segmentValues() [5]M31 {
    return .{
        M31.fromCanonical(11),
        M31.fromCanonical(22),
        M31.one(),
        M31.fromCanonical(33),
        M31.fromCanonical(44),
    };
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
        &segmentValues(),
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
