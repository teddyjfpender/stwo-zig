//! Exactness, adversarial, and hot-path gates for universal PoW row 6.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("pow_check.zig");
const interaction = @import("pow_check_relation.zig");
const support = @import("test_support.zig");
const witness = @import("pow_check_witness.zig");

test "R-012 PoW check pins source, AIR, binding, and framework geometry" {
    const authority = component.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(u8, 68), authority.check_main_columns);
    try std.testing.expectEqual(@as(u8, 126), authority.check_direct_constraints);
    try std.testing.expectEqual(@as(u8, 127), authority.check_framework_constraints);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 68), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 126), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 1), definition.events.len);
    const identity = try component.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );

    const plan = try interaction.authenticate(&definition);
    try std.testing.expectEqual(relation.Domain.recursion_pow_check, plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.validate();
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 PoW check static profile remains quadratic and closed" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = component.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 68), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 126), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 1), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 2), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 PoW check exhausts every difficulty and canonical bit position" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    for (0..component.M31_BIT_COUNT + 1) |bits| {
        const admissible_word: u32 = if (bits == component.M31_BIT_COUNT)
            0
        else
            @as(u32, 1) << @intCast(bits);
        const invocation = fixtureInvocation(@intCast(bits), admissible_word);
        const row = try witness.mainRow(invocation);
        try expectAllRootsZero(&definition, row);
        for (0..component.M31_BIT_COUNT) |bit| {
            try std.testing.expectEqual(
                (admissible_word >> @intCast(bit)) & 1,
                row[6 + bit].v,
            );
            try std.testing.expectEqual(
                @as(u32, @intFromBool(bit < bits)),
                row[6 + component.M31_BIT_COUNT + bit].v,
            );
        }
        if (bits != 0) {
            const forbidden = fixtureInvocation(
                @intCast(bits),
                @as(u32, 1) << @intCast(bits - 1),
            );
            try expectAnyRootNonzero(&definition, try witness.mainRow(forbidden));
        }
    }

    for ([_]u32{ 0, 1, 0x4000_0000, m31.Modulus - 1 }) |word| {
        const row = try witness.mainRow(fixtureInvocation(0, word));
        try expectAllRootsZero(&definition, row);
    }
}

test "R-012 PoW check catches decomposition, prefix, bits, and selector mutations" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const honest = try witness.mainRow(fixtureInvocation(7, 0x1234_5600));
    try expectAllRootsZero(&definition, honest);

    var mutation = honest;
    mutation[6 + 9] = mutation[6 + 9].add(M31.one());
    try expectAnyRootNonzero(&definition, mutation);
    mutation = honest;
    mutation[6 + component.M31_BIT_COUNT + 3] = M31.zero();
    mutation[6 + component.M31_BIT_COUNT + 4] = M31.one();
    try expectAnyRootNonzero(&definition, mutation);
    mutation = honest;
    mutation[4] = mutation[4].add(M31.one());
    try expectAnyRootNonzero(&definition, mutation);
    mutation = honest;
    mutation[0] = M31.fromCanonical(2);
    try expectAnyRootNonzero(&definition, mutation);
}

test "R-012 PoW check relation tuple is exact and consumer signed" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction.authenticate(&definition);
    const invocation = fixtureInvocation(8, 0x1234_5600);
    const row = try witness.mainRow(invocation);
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        row,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    const expected = [_]u32{ 2, 1, 17, 8, 0x1234_5600 };
    for (expected, 0..) |value, index|
        try std.testing.expect(entries[0].values[index].eql(QM31.fromBase(
            M31.fromCanonical(value),
        )));
}

test "R-012 PoW check prepared writer has one cold allocation and no hot allocation" {
    const invocations = [_]witness.Invocation{
        fixtureInvocation(0, m31.Modulus - 1),
        fixtureInvocation(8, 0x1234_5600),
        fixtureInvocation(31, 0),
    };
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try witness.PreparedBatch.init(measured.allocator(), &invocations);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    try batch.validateAgainstSource(&invocations);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const log_size: u32 = 2;
    const size: usize = 1 << log_size;
    var storage: [component.PHYSICAL_MAIN_COLUMN_COUNT * size]M31 =
        .{M31.fromCanonical(77)} ** (component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, &storage, &columns);
    const before = measured.alloc_index;
    try executor.generateMainInto(&batch, &columns, log_size);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (invocations, 0..) |invocation, row_index| {
        const expected = try witness.mainRow(invocation);
        for (columns, expected) |column, value|
            try std.testing.expect(column[row_index].eql(value));
    }
    for (columns) |column| try std.testing.expect(column[3].isZero());

    const snapshot = storage;
    columns[1] = columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&batch, &columns, log_size),
    );
    try std.testing.expectEqualSlices(M31, &snapshot, &storage);
}

test "R-012 PoW check seals mutations and releases every allocation failure" {
    const invocations = [_]witness.Invocation{fixtureInvocation(8, 0x1234_5600)};
    var batch = try witness.PreparedBatch.init(std.testing.allocator, &invocations);
    defer batch.deinit();
    batch.invocations[0].check.nonce ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkBatchFailureCase,
        .{&invocations},
    );
    var invalid = invocations;
    invalid[0].check.bits = 32;
    try std.testing.expectError(
        error.BitsOutOfRange,
        witness.PreparedBatch.init(std.testing.allocator, &invalid),
    );
}

fn fixtureInvocation(bits: u32, word: u32) witness.Invocation {
    return .{
        .verifier_id = 2,
        .kind = .interaction,
        .check = .{
            .call_id = 17,
            .nonce = 0x1122_3344_5566_7788,
            .bits = bits,
            .word = M31.fromCanonical(word),
        },
    };
}

fn expectAllRootsZero(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root|
        try std.testing.expect(values[types.idIndex(root)].isZero());
}

fn expectAnyRootNonzero(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root| {
        if (!values[types.idIndex(root)].isZero()) return;
    }
    return error.TestUnexpectedResult;
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

fn checkBatchFailureCase(
    allocator: std.mem.Allocator,
    invocations: []const witness.Invocation,
) !void {
    var batch = try witness.PreparedBatch.init(allocator, invocations);
    defer batch.deinit();
}
