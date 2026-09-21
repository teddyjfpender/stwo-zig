//! Identity, lane separation, and custody tests for heterogeneous query bits.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");
const subject = @import("query_bits_heterogeneous_v2.zig");
const subject_relation = @import("query_bits_relation_heterogeneous_v2.zig");
const witness = @import("query_bits_witness_heterogeneous_v2.zig");

const VM_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 12,
    .trace_tree_count = 4,
    .fri_layer_count = 2,
};
const LEFT_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 10,
    .trace_tree_count = 4,
    .fri_layer_count = 2,
};
const RIGHT_PROFILE = witness.LaneProfile{
    .query_count = 3,
    .lifting_log_size = 9,
    .trace_tree_count = 5,
    .fri_layer_count = 3,
};

test "R-012 query bits V2 freezes semantic static and witness identities" {
    const identity = try subject.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        subject.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    var definition = try subject.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = subject.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = subject.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 74), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 67), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 33), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 17), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 68), profile.interaction_columns);
    try std.testing.expectEqualStrings(
        subject.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );

    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    _ = try witness.Executor.init(&definition, &binding);
    const interaction = try subject_relation.authenticate(&definition);
    try interaction.validateAgainst(
        &definition.arena,
        subject.SEMANTIC_DIGEST,
        definition.events,
    );
}

test "R-012 query bits V2 authenticates independent lane masks and witnesses" {
    var definition = try subject.build(std.testing.allocator);
    defer definition.deinit();
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);
    try std.testing.expectEqual(@as(usize, 7), preprocessing.rows.len);

    const expected_ids = [_]u32{ 0, 0, 1, 1, 2, 2, 2 };
    const expected_queries = [_]u32{ 0, 1, 0, 1, 0, 1, 2 };
    for (preprocessing.rows, expected_ids, expected_queries) |row, verifier_id, query| {
        try std.testing.expectEqual(verifier_id, row.verifier_id);
        try std.testing.expectEqual(query, row.query);
        const lifting = switch (verifier_id) {
            witness.SEGMENT_VERIFIER_ID => VM_PROFILE.lifting_log_size,
            witness.LEFT_RECURSION_VERIFIER_ID => LEFT_PROFILE.lifting_log_size,
            witness.RIGHT_RECURSION_VERIFIER_ID => RIGHT_PROFILE.lifting_log_size,
            else => unreachable,
        };
        for (row.position_bit_masks, 0..) |mask, bit|
            try std.testing.expectEqual(@as(u32, @intFromBool(bit < lifting)), mask);
    }

    const queries = fixtureQueries();
    const query_witness = witness.QueryWitness{ .binary_node = .{
        .left = &queries.left,
        .right = &queries.right,
    } };
    const parameters = try witness.parameterValues(reference, .binary_node);
    for (preprocessing.rows) |row| {
        const logical = try witness.logicalRow(row, query_witness, parameters);
        try expectSatisfied(&definition, logical);
    }

    // The same authenticated high bit is retained for the left domain and
    // projected to zero for the smaller right domain.
    const high_bit: usize = 9;
    const left = try witness.logicalRow(preprocessing.rows[2], query_witness, parameters);
    const right = try witness.logicalRow(preprocessing.rows[4], query_witness, parameters);
    const left_values = try support.evaluateArena(std.testing.allocator, &definition.arena, &left);
    defer std.testing.allocator.free(left_values);
    const right_values = try support.evaluateArena(std.testing.allocator, &definition.arena, &right);
    defer std.testing.allocator.free(right_values);
    try std.testing.expectEqual(
        @as(u32, 1),
        left_values[types.idIndex(definition.projected_bits[high_bit])].toU32(),
    );
    try std.testing.expect(
        right_values[types.idIndex(definition.projected_bits[high_bit])].isZero(),
    );
}

test "R-012 query bits V2 rejects a forged resealed row authority" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();

    var profile_swap = try witness.Reference.seal(
        VM_PROFILE,
        RIGHT_PROFILE,
        LEFT_PROFILE,
    );
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(profile_swap),
    );
    profile_swap.left.query_count += 1;
    try std.testing.expectError(error.AuthorityMismatch, profile_swap.validate());

    // A public self-hash is not an admission capability: even after an
    // attacker reseals the retained rows, validation reconstructs every row
    // from the trusted three-lane reference.
    preprocessing.rows[2].position_bit_masks[LEFT_PROFILE.lifting_log_size] = 1;
    preprocessing.authority_digest = testRowsDigest(preprocessing.rows);
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

fn fixtureReference() !witness.Reference {
    return witness.Reference.seal(VM_PROFILE, LEFT_PROFILE, RIGHT_PROFILE);
}

const QueryFixture = struct {
    left: [2]M31,
    right: [3]M31,
};

fn fixtureQueries() QueryFixture {
    const word = M31.fromCanonical((@as(u32, 1) << 9) | 5);
    return .{
        .left = .{ word, M31.fromCanonical(77) },
        .right = .{ word, M31.fromCanonical(88), M31.fromCanonical(99) },
    };
}

fn expectSatisfied(
    definition: *const subject.Definition,
    inputs: [subject.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        try std.testing.expect(values[types.idIndex(constraint.root)].isZero());
    }
}

fn testRowsDigest(rows: []const witness.Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-query-bits-rows/v2\x00");
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.row_mask);
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.binary_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.query);
        hashInt(&hash, u32, row.use_count);
        for (row.position_bit_masks) |mask| hashInt(&hash, u32, mask);
    }
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
