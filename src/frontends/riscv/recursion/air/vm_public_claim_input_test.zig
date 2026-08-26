//! Exactness, adversarial, and performance gates for authority-spine row 12.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const types = @import("../../air/lang/types.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const air = @import("vm_public_claim_input.zig");
const witness = @import("vm_public_claim_input_witness.zig");
const relation_plan = @import("vm_public_claim_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");

const SHAPE = witness.Shape{ .max_input_words = 2, .max_output_words = 2 };
const WORD_COUNT = witness.FIXED_CLAIM_WORDS +
    2 * witness.INPUT_SLOT_WORDS + 2 * witness.OUTPUT_SLOT_WORDS;

test "R-012 VM public-claim input preserves exact row-12 geometry and order" {
    const unchecked_identity = try air.semanticIdentity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        air.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(unchecked_identity.bytes, .lower),
    );
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 4), air.PHYSICAL_MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 10), air.PREPROCESSED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 8), air.PARAMETER_COUNT);
    try std.testing.expectEqual(@as(usize, 7), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 8), definition.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 4), relation_plan.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 16), relation_plan.Runtime.INTERACTION_COLUMN_COUNT);

    const expected_domains = [_]relation.Domain{
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_io_word,
        .recursion_vm_public_io_word,
        .range_check_8_8,
        .recursion_vm_public_claim_byte,
        .recursion_vm_public_claim_byte,
    };
    const expected_roles = [_]relation.Role{
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
        .request,
        .emit,
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
    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    _ = try witness.Executor.init(&definition, &binding);
}

test "R-012 VM public-claim input profile is exact and closed" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = air.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = air.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, air.LOGICAL_INPUT_COUNT), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 7), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 8), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 4), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 16), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        air.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 canonical claim shape owns exact classification and IO projections" {
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    try preprocessing.validate();
    try std.testing.expectEqual(@as(usize, WORD_COUNT), preprocessing.rows.len);
    try std.testing.expect(std.meta.eql(
        witness.WordKind{ .constant = 1 },
        preprocessing.rows[0].kind,
    ));
    try std.testing.expectEqual(witness.WordKind.boolean, preprocessing.rows[211].kind);
    try std.testing.expectEqual(witness.WordKind.field, preprocessing.rows[212].kind);
    try std.testing.expectEqual(witness.WordKind.u16, preprocessing.rows[241].kind);
    try std.testing.expectEqual(@as(?u32, 3), preprocessing.rows[241].input_io_index);
    try std.testing.expectEqual(@as(?u32, 3), preprocessing.rows[245].output_io_index);
    try std.testing.expectEqual(witness.WordKind.boolean, preprocessing.rows[256].kind);
    try std.testing.expectEqual(@as(?u32, 9), preprocessing.rows[256].input_io_index);
    try std.testing.expect(std.meta.eql(
        witness.WordKind{ .constant = 13 },
        preprocessing.rows[262].kind,
    ));
    try std.testing.expectEqual(witness.WordKind.boolean, preprocessing.rows[265].kind);
    try std.testing.expectEqual(@as(?u32, 11), preprocessing.rows[265].output_io_index);

    preprocessing.rows[241].input_io_index = 4;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validate());
}

test "R-012 VM public-claim witness covers all modes and rejects every value class" {
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    var words = fixtureWords(&preprocessing);
    var segment = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer segment.deinit();
    try segment.validateAgainst(&preprocessing);
    try std.testing.expectEqual(@as(u32, 4100), segment.rows[241].value.toU32());
    try std.testing.expectEqual(@as(u32, 4), segment.rows[241].low_byte.toU32());
    try std.testing.expectEqual(@as(u32, 16), segment.rows[241].high_byte.toU32());

    for ([_]witness.ProofKind{ .binary_node, .empty_leaf }) |kind| {
        var inactive = try witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            if (kind == .binary_node)
                witness.ClaimWitness{ .binary_node = {} }
            else
                witness.ClaimWitness{ .empty_leaf = {} },
        );
        defer inactive.deinit();
        try inactive.validateAgainst(&preprocessing);
        for (inactive.rows) |row| {
            try std.testing.expect(row.value.isZero());
            try std.testing.expect(row.low_byte.isZero());
            try std.testing.expect(row.high_byte.isZero());
        }
    }

    words[0] = M31.fromCanonical(2);
    try std.testing.expectError(
        error.ConstantMismatch,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            .{ .segment_leaf = &words },
        ),
    );
    words = fixtureWords(&preprocessing);
    words[211] = M31.fromCanonical(2);
    try std.testing.expectError(
        error.InvalidBooleanWord,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            .{ .segment_leaf = &words },
        ),
    );
    words = fixtureWords(&preprocessing);
    words[241] = M31.fromCanonical(65536);
    try std.testing.expectError(
        error.IntegerWordOutOfRange,
        witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            .{ .segment_leaf = &words },
        ),
    );
}

test "R-012 VM public-claim direct constraints hold for all proof modes" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    const words = fixtureWords(&preprocessing);
    const cases = [_]witness.ClaimWitness{
        .{ .segment_leaf = &words },
        .{ .binary_node = {} },
        .{ .empty_leaf = {} },
    };
    for (cases) |claim| {
        var main = try witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            claim,
        );
        defer main.deinit();
        for (main.rows, preprocessing.rows) |main_row, preprocessed_row| {
            const logical = witness.logicalInputs(
                main_row,
                preprocessed_row,
                claim.proofKind(),
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
}

test "R-012 VM public-claim relation weights cover exact source classes" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    const words = fixtureWords(&preprocessing);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer main.deinit();

    const cases = [_]struct { row: usize, nonzero: []const usize }{
        .{ .row = 0, .nonzero = &.{ 0, 1, 2 } },
        .{ .row = 241, .nonzero = &.{ 0, 1, 2, 3, 5, 6, 7 } },
        .{ .row = 245, .nonzero = &.{ 0, 1, 2, 4, 5, 6, 7 } },
        .{ .row = 212, .nonzero = &.{ 0, 1, 2 } },
    };
    for (cases) |case| {
        const entries = try plan.entries(
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            witness.logicalInputs(
                main.rows[case.row],
                preprocessing.rows[case.row],
                .segment_leaf,
            ),
        );
        for (entries, 0..) |entry, event_index| {
            var expected_nonzero = false;
            for (case.nonzero) |index| expected_nonzero =
                expected_nonzero or index == event_index;
            try std.testing.expectEqual(expected_nonzero, !entry.numerator.isZero());
            if (expected_nonzero) {
                const expected_sign = if (event_index == 5)
                    QM31.one().neg()
                else
                    QM31.one();
                try std.testing.expect(entry.numerator.eql(expected_sign));
            }
        }
    }
}

test "R-012 VM public-claim writers are direct padded and failure atomic" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    const words = fixtureWords(&preprocessing);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer main.deinit();
    try assertWriter(
        air.PREPROCESSED_COLUMN_COUNT,
        &preprocessing,
        &executor,
        preprocessing.log_size,
    );
    try assertWriter(
        air.PHYSICAL_MAIN_COLUMN_COUNT,
        &main,
        .{ &preprocessing, &executor },
        preprocessing.log_size,
    );

    var bad_binding = binding;
    bad_binding.main[0].column = 1;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &bad_binding),
    );
}

test "R-012 VM public-claim interaction pins one-inversion five-allocation geometry" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    const words = fixtureWords(&preprocessing);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer main.deinit();
    const rows = try std.testing.allocator.alloc(relation_plan.Row, main.rows.len);
    defer std.testing.allocator.free(rows);
    for (rows, main.rows, preprocessing.rows) |*row, main_row, preprocessed_row|
        row.* = witness.logicalInputs(main_row, preprocessed_row, .segment_leaf);
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            rows,
            preprocessing.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
        try std.testing.expectEqual(@as(usize, 4), interaction.claims.sums.len);
        try std.testing.expectEqual(@as(usize, 16), interaction.columns.len);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, rows, preprocessing.log_size, &relations },
    );
}

test "R-012 VM public-claim construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{},
    );
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, SHAPE);
    defer preprocessing.deinit();
    const words = fixtureWords(&preprocessing);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        mainFailureCase,
        .{ &preprocessing, &words },
    );
}

fn fixtureWords(preprocessing: *const witness.Preprocessed) [WORD_COUNT]M31 {
    var result: [WORD_COUNT]M31 = undefined;
    for (&result, preprocessing.rows, 0..) |*value, row, index| value.* = switch (row.kind) {
        .constant => |constant| M31.fromCanonical(constant),
        .boolean => M31.fromCanonical(@intCast(index & 1)),
        .u16 => M31.fromCanonical(@intCast((index * 17 + 3) & 0xffff)),
        .field => M31.fromCanonical(@intCast(index * 101 + 7)),
    };
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
    if (column_count == air.PREPROCESSED_COLUMN_COUNT) {
        try writer.generateInto(&columns, authority);
    } else {
        try writer.generateInto(&columns, authority[0], authority[1]);
    }
    for (columns) |column| for (column[writer.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    const snapshot = try std.testing.allocator.dupe(M31, storage);
    defer std.testing.allocator.free(snapshot);
    columns[1] = columns[0];
    if (column_count == air.PREPROCESSED_COLUMN_COUNT) {
        try std.testing.expectError(
            error.AliasedDestination,
            writer.generateInto(&columns, authority),
        );
    } else {
        try std.testing.expectError(
            error.AliasedDestination,
            writer.generateInto(&columns, authority[0], authority[1]),
        );
    }
    try std.testing.expectEqualSlices(M31, snapshot, storage);
}

fn buildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try air.build(allocator);
    defer definition.deinit();
}

fn preprocessingFailureCase(allocator: std.mem.Allocator) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, SHAPE);
    defer preprocessing.deinit();
}

fn mainFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    words: *const [WORD_COUNT]M31,
) !void {
    var main = try witness.MainWitness.init(
        allocator,
        preprocessing,
        .{ .segment_leaf = words },
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
