const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_challenges = @import("../relation_challenges.zig");
const registry_mod = @import("relation_registry.zig");
const challenges = @import("relation_challenges.zig");
const relation_event = @import("relation_event.zig");
const types = @import("../lang/types.zig");

test {
    _ = @import("identity_test.zig");
    std.testing.refAllDeclsRecursive(@import("production_adapter.zig"));
}

test "guest relation registry is appended only for the extension profile" {
    const base = registry_mod.Registry.forProfile(.rv32im_zkvm_v1);
    const extension = registry_mod.Registry.forProfile(
        .rv32im_zkvm_poseidon2_v1,
    );

    try std.testing.expectEqual(@as(usize, 12), base.schemaCount());
    try std.testing.expectEqual(@as(usize, 13), extension.schemaCount());
    try std.testing.expect(base.getById(registry_mod.guest_schema_id) == null);
    try std.testing.expect(base.getByIndex(12) == null);

    const schema = extension.getById(registry_mod.guest_schema_id) orelse
        return error.MissingGuestSchema;
    try std.testing.expectEqual(
        registry_mod.guest_schema_id,
        schema.id(),
    );
    try std.testing.expectEqual(@as(u16, 1), schema.version());
    try std.testing.expectEqualStrings(
        "stwo.riscv.guest_poseidon2_io",
        schema.name(),
    );
    try std.testing.expectEqual(@as(usize, 32), schema.fields().len);

    // Every base schema remains at its exact old ID and position in both views.
    for (0..12) |index| {
        const base_schema = base.getByIndex(index) orelse
            return error.MissingBaseSchema;
        const extended_schema = extension.getByIndex(index) orelse
            return error.MissingBaseSchema;
        try std.testing.expectEqual(base_schema.id(), extended_schema.id());
        try std.testing.expectEqualStrings(
            base_schema.name(),
            extended_schema.name(),
        );
        try std.testing.expectEqual(@as(u32, @intCast(index)), @intFromEnum(
            extended_schema.id(),
        ));
    }
    try std.testing.expect(extension.getByIndex(13) == null);
}

test "guest relation schema accepts only 32 felt request or emit fields" {
    const registry = registry_mod.Registry.forProfile(
        .rv32im_zkvm_poseidon2_v1,
    );
    const fields = [_]types.Type{.felt} ** 32;
    try registry.validateEvent(
        registry_mod.guest_schema_id,
        .request,
        &fields,
        null,
    );
    try registry.validateEvent(
        registry_mod.guest_schema_id,
        .emit,
        &fields,
        null,
    );
    try std.testing.expectError(
        error.InvalidRole,
        registry.validateEvent(
            registry_mod.guest_schema_id,
            .consume,
            &fields,
            null,
        ),
    );
    try std.testing.expectError(
        error.UnexpectedAccessOrdinal,
        registry.validateEvent(
            registry_mod.guest_schema_id,
            .request,
            &fields,
            1,
        ),
    );
    try std.testing.expectError(
        error.InvalidArity,
        registry.validateEvent(
            registry_mod.guest_schema_id,
            .request,
            fields[0..31],
            null,
        ),
    );
    var wrong_fields = fields;
    wrong_fields[17] = .byte;
    try std.testing.expectError(
        error.InvalidFieldType,
        registry.validateEvent(
            registry_mod.guest_schema_id,
            .request,
            &wrong_fields,
            null,
        ),
    );
    try std.testing.expectError(
        error.UnknownSchema,
        registry.validateEvent(
            @enumFromInt(13),
            .request,
            &fields,
            null,
        ),
    );
}

test "extension challenge draw is exact base draw followed by one pair" {
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var actual_channel = Channel{};
    var oracle_channel = Channel{};

    const actual = try challenges.Poseidon2V1Relations.draw(
        std.testing.allocator,
        &actual_channel,
    );
    const expected_base = try base_challenges.Relations.draw(
        std.testing.allocator,
        &oracle_channel,
    );
    const guest_draw = try oracle_channel.drawSecureFelts(
        std.testing.allocator,
        2,
    );
    defer std.testing.allocator.free(guest_draw);

    try expectBaseEqual(actual.base, expected_base);
    try std.testing.expect(
        actual.guest_poseidon2_io.z.eql(guest_draw[0]),
    );
    try std.testing.expect(
        actual.guest_poseidon2_io.alpha.eql(guest_draw[1]),
    );
    try std.testing.expect(
        actual_channel.drawSecureFelt().eql(oracle_channel.drawSecureFelt()),
    );
}

test "guest request and provider unit terms cancel without an ordinal field" {
    const relation = challenges.Poseidon2V1Relations.dummy()
        .guest_poseidon2_io;
    var tuple: [32]QM31 = undefined;
    for (&tuple, 0..) |*value, index| {
        value.* = QM31.fromBase(M31.fromCanonical(@intCast(index + 1)));
    }
    const denominator = relation.combineSecure(tuple);
    const inverse = try denominator.inv();
    const request = QM31.one().neg().mul(inverse);
    const provider = QM31.one().mul(inverse);
    try std.testing.expect(request.add(provider).eql(QM31.zero()));

    tuple[31] = tuple[31].add(QM31.one());
    const forged_provider = try relation.combineSecure(tuple).inv();
    try std.testing.expect(!request.add(forged_provider).eql(QM31.zero()));
}

test "guest fixed events enforce unit signs and never invert padding" {
    var tuple: relation_event.Tuple = .{M31.zero()} ** 32;
    tuple[0] = M31.one();
    const relation = challenges.Poseidon2V1Relations.dummy();
    const request = relation_event.Event{
        .role = .request,
        .active = M31.one(),
        .tuple = tuple,
    };
    const provider = relation_event.Event{
        .role = .emit,
        .active = M31.one(),
        .tuple = tuple,
    };
    try std.testing.expect((try request.numerator()).eql(QM31.one().neg()));
    try std.testing.expect((try provider.numerator()).eql(QM31.one()));
    try std.testing.expect(
        (try request.term(&relation)).add(try provider.term(&relation))
            .eql(QM31.zero()),
    );

    // A zero tuple has denominator zero when z=0. Canonical padding still
    // returns zero because the event path never evaluates that denominator.
    var zero_denominator_relations = challenges.Poseidon2V1Relations.dummy();
    zero_denominator_relations.guest_poseidon2_io = .init(
        QM31.zero(),
        QM31.one(),
    );
    const padding = relation_event.Event{
        .role = .request,
        .active = M31.zero(),
        .tuple = .{M31.zero()} ** 32,
    };
    try std.testing.expect(
        (try padding.term(&zero_denominator_relations)).eql(QM31.zero()),
    );

    var malformed_padding = padding;
    malformed_padding.tuple[7] = M31.one();
    try std.testing.expectError(
        error.InvalidPadding,
        malformed_padding.term(&relation),
    );
    var invalid_role = request;
    invalid_role.role = .consume;
    try std.testing.expectError(error.InvalidRole, invalid_role.term(&relation));
    var invalid_liveness = request;
    invalid_liveness.active = M31.fromCanonical(2);
    try std.testing.expectError(
        error.InvalidLiveness,
        invalid_liveness.term(&relation),
    );
}

fn expectBaseEqual(
    actual: base_challenges.Relations,
    expected: base_challenges.Relations,
) !void {
    try expectPairEqual(actual.registers_state, expected.registers_state);
    try expectPairEqual(actual.memory_access, expected.memory_access);
    try expectPairEqual(actual.program_access, expected.program_access);
    try expectPairEqual(actual.merkle, expected.merkle);
    try expectPairEqual(actual.poseidon2, expected.poseidon2);
    try expectPairEqual(actual.poseidon2_io, expected.poseidon2_io);
    try expectPairEqual(actual.bitwise, expected.bitwise);
    try expectPairEqual(actual.range_check_20, expected.range_check_20);
    try expectPairEqual(actual.range_check_8_11, expected.range_check_8_11);
    try expectPairEqual(actual.range_check_8_8_4, expected.range_check_8_8_4);
    try expectPairEqual(actual.range_check_8_8, expected.range_check_8_8);
    try expectPairEqual(actual.range_check_m31, expected.range_check_m31);
}

fn expectPairEqual(actual: anytype, expected: @TypeOf(actual)) !void {
    try std.testing.expect(actual.z.eql(expected.z));
    try std.testing.expect(actual.alpha.eql(expected.alpha));
}
